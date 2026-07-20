//! R3.3 HistoryBase/snapshot persistence and the production atomic installer.
//!
//! This is a child of `index`, intentionally: it needs the same private pooled
//! SQLite connection and `IMMEDIATE` transaction helper as ordinary index/DAG
//! dual writes. Keeping the transition here lets snapshot rows, retained DAG
//! baseline, prune proofs, checkpoint, and HistoryBase move in one transaction.

use std::collections::{BTreeMap, HashMap, HashSet};

use rusqlite::{params, OptionalExtension};

use super::*;
use crate::change::{Change, ChangeHash, FileVersion, Op, SyncPath, VersionHash};
use crate::dag_store::ChangeEmitter;
use crate::compaction::{Checkpoint, CheckpointHash, PrunePlan};
use crate::rebootstrap::{HistoryBase, SnapshotManifest};
use crate::rebootstrap_snapshot::{
    BoundaryParentAuth, RebootstrapSnapshot, SnapshotFile, SnapshotVersionState,
};

fn decode_stored_change(bytes: &[u8]) -> Result<Change, SyncError> {
    Change::from_wire_bytes(bytes).map_err(|error| {
        SyncError::CorruptState(format!("invalid Change in re-bootstrap persistence: {error}"))
    })
}

fn decode_stored_file_version(bytes: &[u8]) -> Result<FileVersion, SyncError> {
    FileVersion::from_canonical_encoding(bytes).map_err(|error| {
        SyncError::CorruptState(format!("invalid FileVersion in re-bootstrap persistence: {error}"))
    })
}

/// The checkpoint hash that immediately preceded this device's own
/// *current* HistoryBase for `group_id` -- `None` if this device has never
/// crossed a compaction/re-bootstrap boundary (its current checkpoint, if
/// any, is the group's genesis) or has no HistoryBase installed at all.
/// Runs against the caller's own connection/transaction so a caller about to
/// overwrite the row (`commit_compaction_snapshot`, `install_rebootstrap_
/// snapshot`) reads the value from *before* that write, within the same
/// atomic transaction.
fn read_history_base_previous_checkpoint_hash(
    conn: &Connection,
    group_id: &str,
) -> Result<Option<[u8; 32]>, SyncError> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT previous_checkpoint_hash FROM group_history_bases WHERE group_id = ?1",
            [group_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    bytes
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                SyncError::CorruptState(format!(
                    "stored previous_checkpoint_hash for group {group_id} is not 32 bytes"
                ))
            })
        })
        .transpose()
}

const REBOOTSTRAP_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS change_checkpoint_snapshots (
    checkpoint_hash BLOB PRIMARY KEY,
    group_id        TEXT NOT NULL,
    snapshot        BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_change_checkpoint_snapshots_group
    ON change_checkpoint_snapshots(group_id);

CREATE TABLE IF NOT EXISTS group_history_bases (
    group_id                 TEXT PRIMARY KEY,
    history_base             BLOB NOT NULL,
    checkpoint_hash          BLOB NOT NULL,
    previous_checkpoint_hash BLOB
);

CREATE TABLE IF NOT EXISTS history_boundary_parent_auth (
    group_id          TEXT NOT NULL,
    checkpoint_hash   BLOB NOT NULL,
    child_hash        BLOB NOT NULL,
    parent_hash       BLOB NOT NULL,
    parent_lamport    INTEGER NOT NULL,
    parent_auth_seq   INTEGER NOT NULL,
    parent_auth_epoch INTEGER NOT NULL,
    PRIMARY KEY (group_id, checkpoint_hash, child_hash, parent_hash)
);
CREATE INDEX IF NOT EXISTS idx_history_boundary_parent_auth_lookup
    ON history_boundary_parent_auth(group_id, child_hash, parent_hash);
"#;

pub(super) fn init_rebootstrap_schema(conn: &Connection) -> Result<(), SyncError> {
    conn.execute_batch(REBOOTSTRAP_SCHEMA)?;
    Ok(())
}

impl SyncState {
    /// Persisted R3.3 history base for a group, if this device has crossed a
    /// compaction/re-bootstrap boundary. `None` is the un-compacted genesis
    /// history, not an error.
    pub fn history_base(&self, group_id: &str) -> Result<Option<HistoryBase>, SyncError> {
        let conn = self.pool.get()?;
        init_rebootstrap_schema(&conn)?;
        let bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT history_base FROM group_history_bases WHERE group_id = ?1",
                [group_id],
                |row| row.get(0),
            )
            .optional()?;
        bytes
            .map(|bytes| {
                let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                    SyncError::CorruptState(format!(
                        "stored HistoryBase for group {group_id} is not 32 bytes"
                    ))
                })?;
                Ok(HistoryBase(array))
            })
            .transpose()
    }

    /// The checkpoint hash that immediately preceded this device's own
    /// *current* HistoryBase for `group_id` -- `None` if this device has
    /// never crossed a compaction/re-bootstrap boundary, or has no
    /// HistoryBase installed at all. Embedded into every `SnapshotManifest`
    /// this device signs for the group (see `prepare_rebootstrap_required`)
    /// as a signed hash-chain link, and the value `install_rebootstrap_
    /// snapshot` requires an incoming manifest's `previous_checkpoint_hash`
    /// to equal before accepting it as a genuine one-hop forward advance.
    pub fn history_base_previous_checkpoint_hash(
        &self,
        group_id: &str,
    ) -> Result<Option<[u8; 32]>, SyncError> {
        let conn = self.pool.get()?;
        init_rebootstrap_schema(&conn)?;
        read_history_base_previous_checkpoint_hash(&conn, group_id)
    }

    pub fn checkpoint_snapshot(
        &self,
        checkpoint_hash: &CheckpointHash,
    ) -> Result<Option<Vec<u8>>, SyncError> {
        let conn = self.pool.get()?;
        init_rebootstrap_schema(&conn)?;
        Ok(conn
            .query_row(
                "SELECT snapshot FROM change_checkpoint_snapshots WHERE checkpoint_hash = ?1",
                [&checkpoint_hash.0[..]],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Authorization coordinates for a parent that is absent specifically
    /// because it crossed the currently retained checkpoint boundary.
    ///
    /// A `history_boundary_parent_auth` row is only trustworthy under the
    /// checkpoint it was written for — it must not be used to vouch for a
    /// parent edge once the group has since switched to a different
    /// HistoryBase (a stale or foreign-checkpoint row proves nothing about
    /// the group's *current* boundary). This joins against
    /// `group_history_bases.checkpoint_hash` (the group's current active
    /// HistoryBase's checkpoint) rather than trusting whatever row happens
    /// to be stored, so a row left over from a since-superseded checkpoint
    /// can never be mistaken for a proof under the current one.
    pub fn compacted_parent_auth(
        &self,
        group_id: &str,
        child_hash: &ChangeHash,
        parent_hash: &ChangeHash,
    ) -> Result<Option<(u64, u64)>, SyncError> {
        let conn = self.pool.get()?;
        init_rebootstrap_schema(&conn)?;
        let row: Option<(i64, i64)> = conn
            .query_row(
                "SELECT h.parent_auth_seq, h.parent_auth_epoch \
                 FROM history_boundary_parent_auth h \
                 JOIN group_history_bases g \
                   ON g.group_id = h.group_id AND g.checkpoint_hash = h.checkpoint_hash \
                 WHERE h.group_id = ?1 AND h.child_hash = ?2 AND h.parent_hash = ?3",
                params![group_id, &child_hash.0[..], &parent_hash.0[..]],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(seq, epoch)| {
            if seq < 0 || epoch < 0 {
                return Err(SyncError::CorruptState(
                    "stored compacted-parent authorization coordinate is negative".into(),
                ));
            }
            Ok((seq as u64, epoch as u64))
        })
        .transpose()
    }

    /// Builds the exact snapshot a destructive compaction will commit.
    ///
    /// The first production implementation deliberately only compacts at the
    /// current DAG frontier. That makes the SQLite materialized/version-history
    /// rows an exact snapshot of the checkpoint cut; compacting to an older cut
    /// would require deterministic historical replay and is rejected rather than
    /// silently hashing the wrong state.
    pub fn build_compaction_snapshot(
        &self,
        plan: &PrunePlan,
    ) -> Result<RebootstrapSnapshot, SyncError> {
        let group_id = plan.group_id.as_str();
        let mut current_heads = self.dag_group_heads(group_id)?;
        current_heads.sort();
        let mut checkpoint_frontier = plan.checkpoint_frontier.clone();
        checkpoint_frontier.sort();
        if current_heads != checkpoint_frontier {
            return Err(SyncError::CorruptState(format!(
                "refusing compaction for group {group_id}: checkpoint frontier is not the current materialized frontier"
            )));
        }
        if plan.pruned.is_empty() {
            return Err(SyncError::CorruptState(
                "cannot build a compaction snapshot for an empty prune".into(),
            ));
        }

        let conn = self.pool.get()?;
        init_rebootstrap_schema(&conn)?;
        let files = read_snapshot_files(&conn, group_id)?;

        let mut versions: BTreeMap<VersionHash, Vec<u8>> = BTreeMap::new();
        for file in &files {
            let version = FileVersion::from_index_row(
                file.record.blocks.clone(),
                file.record.size,
                file.record.mtime_unix_nanos,
                file.record_kind,
                file.exec_bit,
                file.symlink_target.clone(),
            );
            versions.insert(version.version_hash, version.canonical_encoding());
        }

        let pruned: HashSet<ChangeHash> = plan.pruned.iter().copied().collect();
        let mut frontier_changes = Vec::with_capacity(plan.checkpoint_frontier.len());
        let mut boundary_parent_auth = Vec::new();
        for hash in &plan.checkpoint_frontier {
            let encoded = crate::dag_store::get_encoded(&conn, hash)?.ok_or_else(|| {
                SyncError::CorruptState(format!(
                    "checkpoint frontier change {} is missing while building snapshot",
                    hash.to_hex()
                ))
            })?;
            let change = decode_stored_change(&encoded)?;
            if change.group_id.as_str() != group_id {
                return Err(SyncError::CorruptState(
                    "checkpoint frontier contains a foreign-group change".into(),
                ));
            }
            for op in &change.ops {
                if let Some(version_hash) = op_version_hash(op) {
                    let version = crate::dag_store::get_file_version(&conn, group_id, &version_hash)?
                        .ok_or_else(|| {
                            SyncError::CorruptState(format!(
                                "checkpoint frontier references missing file version {}",
                                hex::encode(version_hash.0)
                            ))
                        })?;
                    versions.entry(version_hash).or_insert_with(|| version.canonical_encoding());
                }
            }
            for parent_hash in &change.parents {
                if !pruned.contains(parent_hash) {
                    continue;
                }
                let parent_encoded = crate::dag_store::get_encoded(&conn, parent_hash)?.ok_or_else(|| {
                    SyncError::CorruptState(format!(
                        "pruned checkpoint-boundary parent {} disappeared before snapshot construction",
                        parent_hash.to_hex()
                    ))
                })?;
                let parent = decode_stored_change(&parent_encoded)?;
                boundary_parent_auth.push(BoundaryParentAuth {
                    child_hash: *hash,
                    parent_hash: *parent_hash,
                    parent_lamport: parent.lamport,
                    parent_auth_seq: parent.auth_seq,
                    parent_auth_epoch: parent.auth_epoch,
                });
            }
            frontier_changes.push(encoded);
        }

        RebootstrapSnapshot::new(
            plan.group_id.clone(),
            files,
            frontier_changes,
            versions.into_values().collect(),
            boundary_parent_auth,
        )
    }

    /// Commits checkpoint snapshot + HistoryBase + boundary authorization proof
    /// and deletes the prefix in one SQLite transaction.
    pub fn commit_compaction_snapshot(
        &self,
        checkpoint: &Checkpoint,
        snapshot: &RebootstrapSnapshot,
        pruned: &[ChangeHash],
    ) -> Result<(), SyncError> {
        snapshot.validate_against_checkpoint(checkpoint)?;
        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            init_rebootstrap_schema(&conn)?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let checkpoint_hash = checkpoint.checkpoint_hash();
            tx.execute(
                "INSERT OR REPLACE INTO change_checkpoint_snapshots \
                 (checkpoint_hash, group_id, snapshot) VALUES (?1, ?2, ?3)",
                params![
                    &checkpoint_hash.0[..],
                    checkpoint.group_id.as_str(),
                    snapshot.canonical_encoding(),
                ],
            )?;

            crate::dag_store::commit_prune(&tx, checkpoint, pruned)?;

            // `commit_prune` sweeps versions referenced only by the deleted
            // prefix, and also deletes that prefix's `change_file_versions`
            // rows -- the block-serving justification for any version whose
            // only referencing change was just pruned. Restore both the
            // canonical version bytes and an authorization justification that
            // survives the prune, so a live (current or retained superseded)
            // materialized version never becomes unservable purely because
            // its originating change is gone.
            for encoded in &snapshot.file_versions {
                let version = decode_stored_file_version(encoded)?;
                crate::dag_store::put_file_version(&tx, checkpoint.group_id.as_str(), &version)?;
                crate::dag_store::record_compacted_file_version_authorization(
                    &tx,
                    checkpoint.group_id.as_str(),
                    &version.version_hash,
                )?;
            }

            // A genuine local advance: this device is establishing a NEW
            // checkpoint from its own timeline, so the new checkpoint's
            // `previous_checkpoint_hash` is exactly whatever checkpoint this
            // device currently has installed (its own immediate predecessor
            // in this device's causal history) -- `None` only if this
            // device has never crossed a compaction/re-bootstrap boundary.
            let previous_checkpoint_hash: Option<[u8; 32]> = tx
                .query_row(
                    "SELECT checkpoint_hash FROM group_history_bases WHERE group_id = ?1",
                    [checkpoint.group_id.as_str()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?
                .map(|bytes| {
                    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                        SyncError::CorruptState(
                            "stored HistoryBase checkpoint_hash is not 32 bytes".into(),
                        )
                    })
                })
                .transpose()?;
            persist_history_base_and_boundary(&tx, checkpoint, snapshot, previous_checkpoint_hash)?;
            tx.commit()?;
            Ok(())
        })
    }

    /// Production atomic installer used after a signed snapshot manifest has
    /// been verified. Existing retained branches that are descendants of the
    /// incoming checkpoint frontier are preserved (including offline local
    /// edits reached incrementally); a local head that is genuinely
    /// disconnected from the frontier -- this device was offline and edited
    /// while a peer pruned past their shared ancestor -- is squashed into one
    /// new change re-signed with `local_emitter` and re-parented onto the new
    /// frontier, rather than discarded. `local_emitter` is only needed for
    /// that case; pass `None` when the caller has no signing key on hand (a
    /// disconnected offline branch then falls back to the old fail-closed
    /// behavior: refuse the install rather than silently drop the edit).
    /// Preserved/squashed descendants are left unapplied so the ordinary DAG
    /// projection recovery path replays them on top of the installed baseline.
    pub fn install_rebootstrap_snapshot(
        &self,
        manifest: &SnapshotManifest,
        snapshot_bytes: &[u8],
        local_emitter: Option<&ChangeEmitter>,
    ) -> Result<(), SyncError> {
        let snapshot = RebootstrapSnapshot::decode(snapshot_bytes)?;
        snapshot.validate_against_checkpoint(&manifest.checkpoint)?;
        if snapshot.group_id != manifest.group_id {
            return Err(SyncError::CorruptState(
                "re-bootstrap manifest and snapshot group disagree".into(),
            ));
        }
        let group_id_owned = manifest.group_id.as_str().to_string();
        let local_auth = local_emitter.map(|_| self.local_emission_auth(&group_id_owned)).transpose()?;

        retry_on_database_locked(|| {
            let mut conn = self.pool.get()?;
            init_rebootstrap_schema(&conn)?;
            let tx = new_immediate_write_transaction(&mut conn)?;
            let group_id = manifest.group_id.as_str();
            let frontier: HashSet<ChangeHash> = manifest.checkpoint.frontier.iter().copied().collect();

            // Rollback/fork protection: an independently-valid manifest for
            // this group (a replayed response, an out-of-order delivery, a
            // stale peer, or a genuinely diverged fork from another
            // authorized writer) must not be installed unless it provably,
            // directly extends the HistoryBase this device currently has --
            // `change_checkpoints.seq` alone cannot prove this, it is
            // reassigned locally by whoever installs a manifest and proves
            // nothing about the *signer's* actual causal history. A bare
            // monotonic counter is not sufficient either: two devices'
            // local compaction counts can diverge for a perfectly
            // causally-connected lineage (ordinary incremental DAG sync
            // never touches it), and an unrelated fork can trivially carry
            // a higher count. `manifest.previous_checkpoint_hash` is a
            // signed one-hop hash-chain link, checked here, first, before
            // any other mutation: it must equal exactly what this device
            // currently has installed, or the incoming checkpoint itself
            // must already equal what's installed (a harmless idempotent
            // re-install). A group that has never crossed a compaction/
            // re-bootstrap boundary before (no existing row at all) has
            // nothing to extend or fork away from -- any first manifest is
            // accepted. A receiver more than one compaction behind the
            // signer must catch up via successive re-bootstrap rounds
            // rather than skipping ahead on an unverified claim.
            let current_checkpoint_hash: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT checkpoint_hash FROM group_history_bases WHERE group_id = ?1",
                    [group_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(current_checkpoint_hash) = &current_checkpoint_hash {
                let incoming_checkpoint_hash = manifest.checkpoint.checkpoint_hash();
                let is_idempotent_reinstall = current_checkpoint_hash.as_slice()
                    == &incoming_checkpoint_hash.0[..];
                let is_direct_advance = manifest
                    .previous_checkpoint_hash
                    .is_some_and(|hash| hash[..] == current_checkpoint_hash[..]);
                if !is_idempotent_reinstall && !is_direct_advance {
                    return Err(SyncError::CorruptState(format!(
                        "re-bootstrap manifest for group {group_id} does not directly extend \
                         (previous_checkpoint_hash does not match) the currently installed \
                         HistoryBase; refusing to roll back, fork, or skip ahead without proof \
                         of continuous lineage"
                    )));
                }
            }

            let boundary_parents: HashSet<ChangeHash> =
                snapshot.boundary_parent_auth.iter().map(|edge| edge.parent_hash).collect();
            let reachability = retained_descendants_reaching_frontier(
                &tx,
                group_id,
                &frontier,
                &boundary_parents,
            )?;
            if !reachability.offline_branches.is_empty() && local_emitter.is_none() {
                let head = reachability.offline_branches[0].head;
                return Err(SyncError::CorruptState(format!(
                    "local retained head {} does not descend from incoming checkpoint frontier \
                     and no local signing key was provided to re-emit its offline edits; \
                     refusing to mix HistoryBases",
                    head.to_hex()
                )));
            }
            let retained = reachability.retained;
            replace_group_files_from_snapshot(&tx, group_id, &snapshot.files)?;

            // Remove the old base while retaining only branches demonstrably
            // anchored above the incoming frontier. Frontier bodies themselves
            // are reinstalled from the signed snapshot below. Offline-branch
            // changes are captured in `reachability.offline_branches` already
            // (full Change bodies, not just hashes) and are squashed/re-signed
            // below, so deleting their old rows here loses nothing.
            let existing_hashes: Vec<Vec<u8>> = {
                let mut stmt = tx.prepare("SELECT change_hash FROM changes WHERE group_id = ?1")?;
                let rows = stmt.query_map([group_id], |row| row.get(0))?;
                rows.collect::<Result<_, _>>()?
            };
            for hash_bytes in existing_hashes {
                let Ok(array) = <[u8; 32]>::try_from(hash_bytes.as_slice()) else {
                    return Err(SyncError::CorruptState(
                        "stored change hash is not 32 bytes during re-bootstrap".into(),
                    ));
                };
                let hash = ChangeHash(array);
                if !retained.contains(&hash) && !frontier.contains(&hash) {
                    tx.execute(
                        "DELETE FROM change_file_versions WHERE group_id = ?1 AND change_hash = ?2",
                        params![group_id, &hash.0[..]],
                    )?;
                    tx.execute("DELETE FROM changes WHERE change_hash = ?1", [&hash.0[..]])?;
                }
            }
            tx.execute(
                "DELETE FROM orphan_changes WHERE group_id = ?1",
                [group_id],
            )?;
            tx.execute(
                "DELETE FROM device_frontier WHERE group_id = ?1",
                [group_id],
            )?;

            // The checkpoint insert trigger normally opens a prune context. An
            // install is a base replacement, not evidence that every discarded
            // local row was intentionally pruned by this checkpoint, so close
            // that context before deleting/rebuilding any ancestry rows.
            let checkpoint_hash = manifest.checkpoint.checkpoint_hash();
            let next_seq: i64 = tx.query_row(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM change_checkpoints WHERE group_id = ?1",
                [group_id],
                |row| row.get(0),
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO change_checkpoints \
                 (checkpoint_hash, group_id, snapshot_hash, encoded, seq) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &checkpoint_hash.0[..],
                    group_id,
                    &manifest.checkpoint.snapshot_hash[..],
                    manifest.checkpoint.canonical_encoding(),
                    next_seq,
                ],
            )?;
            tx.execute("DELETE FROM active_prune_context WHERE group_id = ?1", [group_id])?;

            install_snapshot_frontier(&tx, &manifest.checkpoint, &snapshot)?;

            // Squash every offline-diverged branch into one new change per
            // branch, re-parented onto the full new frontier and re-signed
            // with this device's own key -- the original signed `Change`
            // cannot simply be reparented (`parents` is part of its signed,
            // hashed bytes), so a fresh signature is the only valid way to
            // carry the edit forward. Must run after `install_snapshot_frontier`
            // (the frontier changes it parents onto must already be present)
            // and before `rebuild_change_file_version_relations`/
            // `rebuild_group_heads` below (both recompute their state from
            // `changes`, so the squashed change must already be in it).
            for branch in &reachability.offline_branches {
                let emitter = local_emitter.expect(
                    "checked above: offline_branches is non-empty only when local_emitter is Some",
                );
                let auth = local_auth.expect(
                    "checked above: local_auth is Some whenever local_emitter is Some",
                );
                let ops = squash_offline_ops(&branch.chain);
                if ops.is_empty() {
                    continue;
                }
                crate::dag_store::emit_local_change_onto(
                    &tx,
                    group_id,
                    manifest.checkpoint.frontier.clone(),
                    ops,
                    auth,
                    emitter,
                )?;
            }

            for encoded in &snapshot.file_versions {
                let version = decode_stored_file_version(encoded)?;
                crate::dag_store::put_file_version(&tx, group_id, &version)?;
                crate::dag_store::record_compacted_file_version_authorization(
                    &tx,
                    group_id,
                    &version.version_hash,
                )?;
            }

            rebuild_change_file_version_relations(&tx, group_id)?;
            rebuild_group_heads(&tx, group_id)?;

            // Reconcile serving authorization against the newly-installed
            // HistoryBase. The loop above only *adds* to `file_versions`/
            // `compacted_file_version_authorization` (`INSERT OR IGNORE`),
            // so old-HistoryBase rows from a prior compaction lineage would
            // otherwise survive re-bootstrap: `group_file_version_references_block`'s
            // compacted-authorization fallback could then keep authorizing
            // serving of content this new HistoryBase no longer retains.
            // The authorized set is exactly the snapshot's own file versions
            // plus whatever `change_file_versions` (just rebuilt above)
            // shows the retained descendants still reference — replace the
            // group's authorization table with precisely that set, then
            // sweep now-unauthorized `file_versions` rows.
            // `group_block_provenance` is deliberately left untouched: it is
            // block-level and group-membership-scoped by design, not
            // version-scoped, so it does not participate in this
            // reconciliation.
            let mut authorized_versions: HashSet<VersionHash> = HashSet::new();
            for encoded in &snapshot.file_versions {
                authorized_versions.insert(decode_stored_file_version(encoded)?.version_hash);
            }
            {
                let mut stmt = tx.prepare(
                    "SELECT DISTINCT version_hash FROM change_file_versions WHERE group_id = ?1",
                )?;
                let rows = stmt.query_map([group_id], |row| row.get::<_, Vec<u8>>(0))?;
                for row in rows {
                    let bytes = row?;
                    let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                        SyncError::CorruptState(
                            "stored change_file_versions version hash is not 32 bytes".into(),
                        )
                    })?;
                    authorized_versions.insert(VersionHash(array));
                }
            }
            tx.execute(
                "DELETE FROM compacted_file_version_authorization WHERE group_id = ?1",
                [group_id],
            )?;
            for version_hash in &authorized_versions {
                crate::dag_store::record_compacted_file_version_authorization(
                    &tx,
                    group_id,
                    version_hash,
                )?;
            }
            crate::dag_store::sweep_unreferenced_file_versions(&tx, group_id)?;

            // Snapshot frontier effects are already represented in the baseline
            // file rows, so the frontier itself is applied. Every retained
            // descendant is left unapplied so `reproject_unapplied_changes`'s
            // ordinary backstop replays it on top of the installed baseline.
            tx.execute("UPDATE changes SET applied = 0 WHERE group_id = ?1", [group_id])?;
            for hash in &manifest.checkpoint.frontier {
                tx.execute(
                    "UPDATE changes SET applied = 1 WHERE group_id = ?1 AND change_hash = ?2",
                    params![group_id, &hash.0[..]],
                )?;
            }

            tx.execute(
                "INSERT OR REPLACE INTO change_checkpoint_snapshots \
                 (checkpoint_hash, group_id, snapshot) VALUES (?1, ?2, ?3)",
                params![&checkpoint_hash.0[..], group_id, snapshot_bytes],
            )?;
            persist_history_base_and_boundary(
                &tx,
                &manifest.checkpoint,
                &snapshot,
                manifest.previous_checkpoint_hash,
            )?;
            tx.commit()?;
            Ok(())
        })
    }
}

fn read_snapshot_files(conn: &Connection, group_id: &str) -> Result<Vec<SnapshotFile>, SyncError> {
    let mut stmt = conn.prepare(
        "SELECT path, size, mtime_unix_nanos, version_json, blocks_json, deleted, \
                version_seq, state, origin_device_id, record_kind, symlink_target, \
                exec_bit, symlink_out_of_root \
         FROM files WHERE group_id = ?1 ORDER BY path, version_seq",
    )?;
    let rows = stmt.query_map([group_id], |row| {
        let version_json: String = row.get(3)?;
        let blocks_json: String = row.get(4)?;
        let counters: BTreeMap<String, u64> = serde_json::from_str(&version_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
        let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
        let state_text: String = row.get(7)?;
        let state = SnapshotVersionState::from_db_str(&state_text).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown file version state {state_text}"),
                )),
            )
        })?;
        Ok(SnapshotFile {
            record: FileRecord {
                path: row.get(0)?,
                size: row.get::<_, i64>(1)? as u64,
                mtime_unix_nanos: row.get(2)?,
                version: VersionVector::from_counters(counters),
                blocks,
                deleted: row.get::<_, i64>(5)? != 0,
            },
            version_seq: row.get(6)?,
            state,
            origin_device_id: row.get(8)?,
            record_kind: RecordKind::from_db_str(&row.get::<_, String>(9)?),
            symlink_target: row.get(10)?,
            exec_bit: row.get::<_, i64>(11)? != 0,
            symlink_out_of_root: row.get::<_, i64>(12)? != 0,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn persist_history_base_and_boundary(
    conn: &Connection,
    checkpoint: &Checkpoint,
    snapshot: &RebootstrapSnapshot,
    previous_checkpoint_hash: Option<[u8; 32]>,
) -> Result<(), SyncError> {
    let checkpoint_hash = checkpoint.checkpoint_hash();
    let history_base = HistoryBase::from_checkpoint(checkpoint);
    conn.execute(
        "INSERT OR REPLACE INTO group_history_bases \
         (group_id, history_base, checkpoint_hash, previous_checkpoint_hash) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            checkpoint.group_id.as_str(),
            &history_base.0[..],
            &checkpoint_hash.0[..],
            previous_checkpoint_hash.as_ref().map(|h| &h[..]),
        ],
    )?;
    conn.execute(
        "DELETE FROM history_boundary_parent_auth WHERE group_id = ?1",
        [checkpoint.group_id.as_str()],
    )?;
    for edge in &snapshot.boundary_parent_auth {
        conn.execute(
            "INSERT INTO history_boundary_parent_auth \
             (group_id, checkpoint_hash, child_hash, parent_hash, parent_lamport, parent_auth_seq, parent_auth_epoch) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                checkpoint.group_id.as_str(),
                &checkpoint_hash.0[..],
                &edge.child_hash.0[..],
                &edge.parent_hash.0[..],
                edge.parent_lamport as i64,
                edge.parent_auth_seq as i64,
                edge.parent_auth_epoch as i64,
            ],
        )?;
    }
    Ok(())
}

fn replace_group_files_from_snapshot(
    conn: &Connection,
    group_id: &str,
    files: &[SnapshotFile],
) -> Result<(), SyncError> {
    conn.execute("DELETE FROM files WHERE group_id = ?1", [group_id])?;
    for file in files {
        let version_json = serde_json::to_string(file.record.version.counters())?;
        let blocks_json = serde_json::to_string(&file.record.blocks)?;
        let materialization_state = if file.state == SnapshotVersionState::Current
            && !file.record.deleted
        {
            "placeholder"
        } else {
            "hydrated"
        };
        conn.execute(
            "INSERT INTO files \
             (group_id, path, size, mtime_unix_nanos, version_json, blocks_json, deleted, \
              version_seq, state, origin_device_id, materialization_state, pinned, \
              record_kind, symlink_target, exec_bit, symlink_out_of_root) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12, ?13, ?14, ?15)",
            params![
                group_id,
                &file.record.path,
                file.record.size as i64,
                file.record.mtime_unix_nanos,
                version_json,
                blocks_json,
                file.record.deleted as i64,
                file.version_seq,
                file.state.as_db_str(),
                file.origin_device_id.as_deref(),
                materialization_state,
                file.record_kind.as_db_str(),
                file.symlink_target.as_deref(),
                file.exec_bit as i64,
                file.symlink_out_of_root as i64,
            ],
        )?;
    }
    Ok(())
}

/// A local head that does not descend from an incoming checkpoint frontier
/// (the offline-diverged-branch case re-bootstrap exists to rescue: this
/// device made local edits while disconnected, and a peer pruned past their
/// shared ancestor), together with its full local-only ancestry captured
/// before the old base is deleted. `chain` is ordered oldest-first
/// (ascending lamport, ties broken by hash for determinism) -- ready to
/// squash into one new change re-parented onto the new frontier.
struct OfflineBranch {
    head: ChangeHash,
    chain: Vec<Change>,
}

struct FrontierReachability {
    /// Retained descendants of the incoming frontier, left unapplied for the
    /// ordinary reprojection backstop to replay.
    retained: HashSet<ChangeHash>,
    /// Local heads that do not descend from the frontier at all.
    offline_branches: Vec<OfflineBranch>,
}

fn retained_descendants_reaching_frontier(
    conn: &Connection,
    group_id: &str,
    frontier: &HashSet<ChangeHash>,
    boundary_parents: &HashSet<ChangeHash>,
) -> Result<FrontierReachability, SyncError> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut stmt = conn.prepare("SELECT change_hash, encoded FROM changes WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    if rows.is_empty() {
        return Ok(FrontierReachability { retained: HashSet::new(), offline_branches: Vec::new() });
    }
    let mut changes = HashMap::new();
    for (hash_bytes, encoded) in rows {
        let array: [u8; 32] = hash_bytes.as_slice().try_into().map_err(|_| {
            SyncError::CorruptState("stored change hash is not 32 bytes during re-bootstrap".into())
        })?;
        let hash = ChangeHash(array);
        let change = decode_stored_change(&encoded)?;
        if change.compute_hash() != hash {
            return Err(SyncError::CorruptState(
                "stored change bytes disagree with their key during re-bootstrap".into(),
            ));
        }
        changes.insert(hash, change);
    }

    let heads: Vec<ChangeHash> = crate::dag_store::group_heads(conn, group_id)?;
    let mut memo: HashMap<ChangeHash, bool> = HashMap::new();
    fn reaches(
        hash: ChangeHash,
        frontier: &HashSet<ChangeHash>,
        changes: &HashMap<ChangeHash, Change>,
        memo: &mut HashMap<ChangeHash, bool>,
        visiting: &mut HashSet<ChangeHash>,
    ) -> bool {
        if frontier.contains(&hash) {
            memo.insert(hash, true);
            return true;
        }
        if let Some(value) = memo.get(&hash) {
            return *value;
        }
        if !visiting.insert(hash) {
            memo.insert(hash, false);
            return false;
        }
        let result = changes.get(&hash).is_some_and(|change| {
            change.parents.iter().any(|parent| {
                reaches(*parent, frontier, changes, memo, visiting)
            })
        });
        visiting.remove(&hash);
        memo.insert(hash, result);
        result
    }

    // A head that fails to reach the frontier means -- by construction of
    // `reaches`'s memoized parent walk -- that NO ancestor of it reaches the
    // frontier either: its entire local ancestry back to the group root is
    // disconnected from the incoming HistoryBase. That whole chain is offline
    // edit material to squash and re-emit, not evidence to refuse the install.
    let mut reaching_heads = Vec::new();
    let mut offline_heads = Vec::new();
    for head in &heads {
        if reaches(*head, frontier, &changes, &mut memo, &mut HashSet::new()) {
            reaching_heads.push(*head);
        } else {
            offline_heads.push(*head);
        }
    }

    let mut retained = HashSet::new();
    let mut stack = reaching_heads;
    while let Some(hash) = stack.pop() {
        if !retained.insert(hash) || frontier.contains(&hash) {
            continue;
        }
        if let Some(change) = changes.get(&hash) {
            for parent in &change.parents {
                if frontier.contains(parent)
                    || memo.get(parent).copied().unwrap_or(false)
                {
                    stack.push(*parent);
                }
            }
        }
    }

    let mut offline_branches = Vec::new();
    for head in offline_heads {
        let mut visited = HashSet::new();
        let mut branch_stack = vec![head];
        let mut chain = Vec::new();
        while let Some(hash) = branch_stack.pop() {
            if !visited.insert(hash) {
                continue;
            }
            // An ancestor that exactly matches one of the new frontier's own
            // pruned-boundary parents is proven -- by that same boundary
            // proof -- to already be incorporated into the new baseline
            // snapshot. It (and everything at-or-before it) is shared
            // history, not offline-only material: stop here rather than
            // re-including already-baked-in ops in the squash, which could
            // otherwise clobber content the new frontier's own later history
            // established on the same path after this shared point.
            if boundary_parents.contains(&hash) {
                continue;
            }
            if let Some(change) = changes.get(&hash) {
                chain.push(change.clone());
                for parent in &change.parents {
                    branch_stack.push(*parent);
                }
            }
        }
        chain.sort_by_key(|c| (c.lamport, c.compute_hash().0));
        offline_branches.push(OfflineBranch { head, chain });
    }

    Ok(FrontierReachability { retained, offline_branches })
}

/// Squashes an offline-diverged local branch's ops into one final op set per
/// path, last-write-wins across the chain (already ordered oldest-first).
/// `FileVersion`/`VersionHash` content is copied forward unchanged -- ops are
/// content-addressed and independent of lineage, so no transformation is
/// needed there. A `Move` is folded into a delete-at-source plus an
/// update-at-destination for squash bookkeeping: the destination's content is
/// preserved exactly, only the rename's provenance across the squash boundary
/// is not (a new frontier-attached change is being minted regardless, so nothing
/// downstream depends on that provenance surviving).
fn squash_offline_ops(chain: &[Change]) -> Vec<Op> {
    #[derive(Clone, Copy)]
    enum PathState {
        Present { version: VersionHash, is_new: bool },
        Deleted,
    }

    let mut state: BTreeMap<String, PathState> = BTreeMap::new();
    for change in chain {
        for op in &change.ops {
            match op {
                Op::Create { path, version } => {
                    state.insert(path.as_str().to_string(), PathState::Present {
                        version: *version,
                        is_new: true,
                    });
                }
                Op::Update { path, version } => {
                    let is_new = matches!(
                        state.get(path.as_str()),
                        None | Some(PathState::Present { is_new: true, .. })
                    );
                    state.insert(path.as_str().to_string(), PathState::Present {
                        version: *version,
                        is_new,
                    });
                }
                Op::Delete { path } => {
                    state.insert(path.as_str().to_string(), PathState::Deleted);
                }
                Op::Move { from, to, version } => {
                    state.insert(from.as_str().to_string(), PathState::Deleted);
                    state.insert(to.as_str().to_string(), PathState::Present {
                        version: *version,
                        is_new: false,
                    });
                }
            }
        }
    }

    state
        .into_iter()
        .map(|(path, path_state)| match path_state {
            PathState::Present { version, is_new: true } => {
                Op::Create { path: SyncPath(path), version }
            }
            PathState::Present { version, is_new: false } => {
                Op::Update { path: SyncPath(path), version }
            }
            PathState::Deleted => Op::Delete { path: SyncPath(path) },
        })
        .collect()
}

fn install_snapshot_frontier(
    conn: &Connection,
    checkpoint: &Checkpoint,
    snapshot: &RebootstrapSnapshot,
) -> Result<(), SyncError> {
    let group_id = checkpoint.group_id.as_str();
    // `boundary_parent_auth` is the exhaustive, authoritative list of parent
    // edges that point at pruned checkpoint-boundary ancestors rather than at
    // another live frontier member. Those edges belong exclusively in
    // `pruned_change_parents` (written below); a frontier change's remaining
    // parents (other frontier members) are the only ones that belong in the
    // ordinary live `change_parents` table. The startup integrity validator
    // (`retained_history_integrity::retained_parent_edges_match`) treats live
    // and pruned edges as mutually exclusive per (child, parent) pair and
    // fail-closes on reopen if both exist for the same pair.
    let boundary_edges: std::collections::HashSet<(ChangeHash, ChangeHash)> = snapshot
        .boundary_parent_auth
        .iter()
        .map(|edge| (edge.child_hash, edge.parent_hash))
        .collect();
    for encoded in &snapshot.frontier_changes {
        let change = decode_stored_change(encoded)?;
        let hash = change.compute_hash();
        conn.execute(
            "INSERT OR REPLACE INTO changes \
             (change_hash, group_id, device_id, lamport, encoded, applied) \
             VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![
                &hash.0[..],
                group_id,
                change.device_id.as_str(),
                change.lamport as i64,
                encoded,
            ],
        )?;
        conn.execute("DELETE FROM change_parents WHERE child_hash = ?1", [&hash.0[..]])?;
        for parent in &change.parents {
            if boundary_edges.contains(&(hash, *parent)) {
                continue;
            }
            conn.execute(
                "INSERT OR IGNORE INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
                params![&hash.0[..], &parent.0[..]],
            )?;
        }
    }

    // Recreate the compact structural proof for direct parents omitted from the
    // snapshot. This is bounded to boundary edges, not the full pruned prefix.
    let checkpoint_hash = checkpoint.checkpoint_hash();
    for edge in &snapshot.boundary_parent_auth {
        conn.execute(
            "INSERT OR REPLACE INTO pruned_changes \
             (group_id, change_hash, checkpoint_hash, lamport) VALUES (?1, ?2, ?3, ?4)",
            params![
                group_id,
                &edge.parent_hash.0[..],
                &checkpoint_hash.0[..],
                edge.parent_lamport as i64,
            ],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO pruned_change_parents \
             (group_id, child_hash, parent_hash, checkpoint_hash) VALUES (?1, ?2, ?3, ?4)",
            params![
                group_id,
                &edge.child_hash.0[..],
                &edge.parent_hash.0[..],
                &checkpoint_hash.0[..],
            ],
        )?;
    }
    Ok(())
}

fn rebuild_change_file_version_relations(
    conn: &Connection,
    group_id: &str,
) -> Result<(), SyncError> {
    conn.execute("DELETE FROM change_file_versions WHERE group_id = ?1", [group_id])?;
    let changes: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT change_hash, encoded FROM changes WHERE group_id = ?1",
        )?;
        let rows = stmt.query_map([group_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    for (hash_bytes, encoded) in changes {
        let hash: [u8; 32] = hash_bytes.as_slice().try_into().map_err(|_| {
            SyncError::CorruptState("stored change hash is not 32 bytes".into())
        })?;
        let change = decode_stored_change(&encoded)?;
        for op in &change.ops {
            if let Some(version_hash) = op_version_hash(op) {
                conn.execute(
                    "INSERT OR IGNORE INTO change_file_versions \
                     (group_id, change_hash, version_hash) VALUES (?1, ?2, ?3)",
                    params![group_id, &hash[..], &version_hash.0[..]],
                )?;
            }
        }
    }
    Ok(())
}

fn rebuild_group_heads(conn: &Connection, group_id: &str) -> Result<(), SyncError> {
    conn.execute("DELETE FROM group_heads WHERE group_id = ?1", [group_id])?;
    conn.execute(
        "INSERT INTO group_heads (group_id, change_hash) \
         SELECT ?1, c.change_hash FROM changes c \
         WHERE c.group_id = ?1 \
           AND NOT EXISTS (\
             SELECT 1 FROM change_parents cp \
             JOIN changes child ON child.change_hash = cp.child_hash \
             WHERE cp.parent_hash = c.change_hash AND child.group_id = ?1\
           )",
        [group_id],
    )?;
    Ok(())
}

fn op_version_hash(op: &Op) -> Option<VersionHash> {
    match op {
        Op::Create { version, .. } | Op::Update { version, .. } | Op::Move { version, .. } => {
            Some(*version)
        }
        Op::Delete { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::change::{ChangeAuth, DeviceId, SyncPath};

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn group() -> FolderGroupId {
        FolderGroupId("g".into())
    }

    fn delete_change(
        parents: Vec<ChangeHash>,
        lamport: u64,
        device: &str,
        path: &str,
        signing: &SigningKey,
    ) -> Change {
        Change::create_signed(
            parents,
            lamport,
            ChangeAuth::PLACEHOLDER,
            DeviceId(device.into()),
            group(),
            vec![Op::Delete { path: SyncPath(path.into()) }],
            signing,
        )
    }

    /// A real destructive prune (`build_compaction_snapshot` +
    /// `commit_compaction_snapshot`) against a real `SyncState`, followed by a
    /// real `install_rebootstrap_snapshot` against a *different* device's
    /// `SyncState` that has its own unrelated local descendant of the frontier.
    /// Every other test of this pipeline runs against `MockStore`/`FakeStore`
    /// fakes; this is the only test that exercises the actual SQLite installer.
    #[test]
    fn a_real_prune_snapshot_installs_onto_another_devices_state_preserving_its_local_descendant() {
        let signing = signing_key(1);

        let sender = SyncState::open_in_memory().unwrap();
        let a = delete_change(vec![], 0, "device-a", "a.bin", &signing);
        sender.dag_admit_change(&a, true).unwrap();
        let b = delete_change(vec![a.compute_hash()], 1, "device-a", "b.bin", &signing);
        sender.dag_admit_change(&b, true).unwrap();
        assert_eq!(sender.dag_group_heads("g").unwrap(), vec![b.compute_hash()]);

        let plan = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![b.compute_hash()],
            pruned: vec![a.compute_hash()],
            blocking_devices: vec![],
        };
        let snapshot = sender.build_compaction_snapshot(&plan).unwrap();
        let checkpoint = Checkpoint::new(group(), plan.checkpoint_frontier.clone(), snapshot.snapshot_hash());
        sender.commit_compaction_snapshot(&checkpoint, &snapshot, &plan.pruned).unwrap();

        // The pruned prefix is really gone, and the new HistoryBase is recorded.
        assert_eq!(sender.dag_group_heads("g").unwrap(), vec![b.compute_hash()]);
        assert_eq!(sender.dag_parents_of(&b.compute_hash()).unwrap(), Vec::<ChangeHash>::new());
        assert_eq!(sender.history_base("g").unwrap(), Some(HistoryBase::from_checkpoint(&checkpoint)));
        let snapshot_bytes = sender.checkpoint_snapshot(&checkpoint.checkpoint_hash()).unwrap().unwrap();
        assert_eq!(snapshot_bytes, snapshot.canonical_encoding());

        // A receiving device already has the full pre-compaction history (it
        // never compacted locally) plus its own later local edit that must
        // survive the base switch.
        let receiver = SyncState::open_in_memory().unwrap();
        receiver.dag_admit_change(&a, true).unwrap();
        receiver.dag_admit_change(&b, true).unwrap();
        let d = delete_change(vec![b.compute_hash()], 2, "device-b", "d.bin", &signing);
        receiver.dag_admit_change(&d, false).unwrap();
        assert_eq!(receiver.dag_group_heads("g").unwrap(), vec![d.compute_hash()]);

        let manifest = SnapshotManifest::new_signed(
            checkpoint.clone(),
            vec![b.compute_hash()],
            None,
            DeviceId("device-a".into()),
            &signing,
        )
        .unwrap();
        receiver.install_rebootstrap_snapshot(&manifest, &snapshot_bytes, None).unwrap();

        // The retained local descendant must survive the install...
        assert_eq!(receiver.dag_group_heads("g").unwrap(), vec![d.compute_hash()]);
        assert!(receiver.dag_parents_of(&d.compute_hash()).unwrap().contains(&b.compute_hash()));
        // ...frontier is applied (its effects are already in the baseline)...
        assert!(receiver.dag_list_unapplied_changes("g").unwrap().iter().all(|c| c.compute_hash() != b.compute_hash()));
        // ...but the retained descendant is left unapplied for the ordinary
        // reprojection backstop to replay onto the fresh baseline.
        assert!(receiver.dag_list_unapplied_changes("g").unwrap().iter().any(|c| c.compute_hash() == d.compute_hash()));
        assert_eq!(
            receiver.history_base("g").unwrap(),
            Some(HistoryBase::from_checkpoint(&checkpoint))
        );
    }

    /// A real prune records a `history_boundary_parent_auth` row that
    /// `compacted_parent_auth` can find under the group's current
    /// HistoryBase, but a row left over from some *other*, non-current
    /// checkpoint must never be returned — it proves nothing about the
    /// group's current boundary. This is the anchoring
    /// `compacted_parent_auth` must enforce so a stale or foreign-checkpoint
    /// row can't be mistaken for a proof under the checkpoint actually
    /// installed.
    #[test]
    fn compacted_parent_auth_ignores_rows_under_a_non_current_checkpoint() {
        let signing = signing_key(4);

        let sender = SyncState::open_in_memory().unwrap();
        let a = delete_change(vec![], 0, "device-a", "a.bin", &signing);
        sender.dag_admit_change(&a, true).unwrap();
        let b = delete_change(vec![a.compute_hash()], 1, "device-a", "b.bin", &signing);
        sender.dag_admit_change(&b, true).unwrap();

        let plan = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![b.compute_hash()],
            pruned: vec![a.compute_hash()],
            blocking_devices: vec![],
        };
        let snapshot = sender.build_compaction_snapshot(&plan).unwrap();
        let checkpoint = Checkpoint::new(group(), plan.checkpoint_frontier.clone(), snapshot.snapshot_hash());
        sender.commit_compaction_snapshot(&checkpoint, &snapshot, &plan.pruned).unwrap();

        // The real boundary edge b -> a is found under the current checkpoint.
        assert!(sender
            .compacted_parent_auth("g", &b.compute_hash(), &a.compute_hash())
            .unwrap()
            .is_some());

        // A row for the same (child, parent) pair, but stamped with a
        // checkpoint_hash that is NOT the group's current one, must not be
        // returned -- it does not prove anything about the group's current
        // boundary, no matter how it got there (a stale leftover, a
        // differently-keyed peer's checkpoint, or a forged value).
        let conn = sender.pool.get().unwrap();
        let unrelated = delete_change(vec![], 0, "device-c", "unrelated.bin", &signing);
        let stale_checkpoint_hash = [0x42u8; 32];
        conn.execute(
            "INSERT OR REPLACE INTO history_boundary_parent_auth \
             (group_id, checkpoint_hash, child_hash, parent_hash, parent_lamport, \
              parent_auth_seq, parent_auth_epoch) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                "g",
                &stale_checkpoint_hash[..],
                &unrelated.compute_hash().0[..],
                &a.compute_hash().0[..],
                0i64,
                0i64,
                0i64,
            ],
        )
        .unwrap();
        drop(conn);
        assert!(sender
            .compacted_parent_auth("g", &unrelated.compute_hash(), &a.compute_hash())
            .unwrap()
            .is_none());
    }

    /// A frontier change whose parent is a pruned checkpoint-boundary parent
    /// must record that edge *only* in `pruned_change_parents`, never also in
    /// the live `change_parents` table — the startup integrity validator
    /// treats the two as mutually exclusive per `(child, parent)` pair and
    /// fail-closes on the next schema/repair pass if both exist. This test
    /// reproduces the install, then re-runs the same repair pass a real
    /// process restart would run (`init_dag_schema`, which calls
    /// `retained_history_integrity::repair` unconditionally) against the
    /// installed connection, asserting it still succeeds.
    #[test]
    fn install_snapshot_frontier_survives_repair_on_reopen() {
        let signing = signing_key(3);

        let sender = SyncState::open_in_memory().unwrap();
        let a = delete_change(vec![], 0, "device-a", "a.bin", &signing);
        sender.dag_admit_change(&a, true).unwrap();
        let b = delete_change(vec![a.compute_hash()], 1, "device-a", "b.bin", &signing);
        sender.dag_admit_change(&b, true).unwrap();

        let plan = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![b.compute_hash()],
            pruned: vec![a.compute_hash()],
            blocking_devices: vec![],
        };
        let snapshot = sender.build_compaction_snapshot(&plan).unwrap();
        let checkpoint = Checkpoint::new(group(), plan.checkpoint_frontier.clone(), snapshot.snapshot_hash());
        sender.commit_compaction_snapshot(&checkpoint, &snapshot, &plan.pruned).unwrap();
        let snapshot_bytes = sender.checkpoint_snapshot(&checkpoint.checkpoint_hash()).unwrap().unwrap();

        let receiver = SyncState::open_in_memory().unwrap();
        let manifest = SnapshotManifest::new_signed(
            checkpoint,
            vec![b.compute_hash()],
            None,
            DeviceId("device-a".into()),
            &signing,
        )
        .unwrap();
        receiver.install_rebootstrap_snapshot(&manifest, &snapshot_bytes, None).unwrap();

        // Simulate a process restart: re-run the same schema/repair pass
        // `SyncState::open`/`open_in_memory` runs on every open. Before the
        // fix, `b`'s pruned-boundary parent `a` would be present in both
        // `change_parents` and `pruned_change_parents`, and this would fail
        // closed with a "live/pruned parent-edge proofs disagree" error.
        let conn = receiver.pool.get().unwrap();
        crate::dag_store::init_dag_schema(&conn).expect(
            "repair on reopen must succeed: a frontier change's pruned-boundary \
             parent must not also be recorded as a live change_parents edge",
        );
    }

    /// A receiving device whose retained head does *not* descend from the
    /// incoming checkpoint frontier, with no local signing key available to
    /// re-emit its offline edits, must be refused -- not silently mixed with
    /// an unrelated HistoryBase, and not silently dropped either.
    #[test]
    fn install_refuses_a_retained_head_that_does_not_descend_from_the_incoming_frontier() {
        let signing = signing_key(2);

        let sender = SyncState::open_in_memory().unwrap();
        let a = delete_change(vec![], 0, "device-a", "a.bin", &signing);
        sender.dag_admit_change(&a, true).unwrap();
        let b = delete_change(vec![a.compute_hash()], 1, "device-a", "b.bin", &signing);
        sender.dag_admit_change(&b, true).unwrap();
        let plan = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![b.compute_hash()],
            pruned: vec![a.compute_hash()],
            blocking_devices: vec![],
        };
        let snapshot = sender.build_compaction_snapshot(&plan).unwrap();
        let checkpoint = Checkpoint::new(group(), plan.checkpoint_frontier.clone(), snapshot.snapshot_hash());
        sender.commit_compaction_snapshot(&checkpoint, &snapshot, &plan.pruned).unwrap();
        let snapshot_bytes = sender.checkpoint_snapshot(&checkpoint.checkpoint_hash()).unwrap().unwrap();

        // The receiver's own head is a totally unrelated root, sharing no
        // ancestry with the incoming checkpoint frontier at all.
        let receiver = SyncState::open_in_memory().unwrap();
        let unrelated = delete_change(vec![], 0, "device-c", "unrelated.bin", &signing);
        receiver.dag_admit_change(&unrelated, true).unwrap();

        let manifest = SnapshotManifest::new_signed(
            checkpoint,
            vec![b.compute_hash()],
            None,
            DeviceId("device-a".into()),
            &signing,
        )
        .unwrap();
        let error =
            receiver.install_rebootstrap_snapshot(&manifest, &snapshot_bytes, None).unwrap_err();
        assert!(
            matches!(error, SyncError::CorruptState(ref message) if message.contains("does not descend")),
            "unexpected error: {error:?}"
        );
    }

    /// REQUIRED RED (both reviews): device 1 goes offline and edits locally
    /// (`a` -> `b`, a Create nowhere in device 2's history); device 2
    /// advances `a` -> `c`, checkpoints `c`, and prunes `a`. When device 1
    /// re-bootstraps onto device 2's checkpoint, `b` does not descend from
    /// `c` -- but its content must survive, squashed into one new change
    /// re-signed by device 1 and re-parented directly onto the new frontier,
    /// not silently discarded. The squashed change must also survive the
    /// same repair-on-reopen pass `install_snapshot_frontier_survives_repair_on_reopen`
    /// exercises.
    #[test]
    fn install_rebootstrap_snapshot_squashes_an_offline_diverged_branch() {
        let sender_signing = signing_key(10);
        let receiver_signing = signing_key(11);

        // The shared root both devices started from.
        let a = delete_change(vec![], 0, "device-shared", "shared.bin", &sender_signing);

        // Device 2 (sender): advances a -> c, checkpoints c, prunes a.
        let sender = SyncState::open_in_memory().unwrap();
        sender.dag_admit_change(&a, true).unwrap();
        let c = delete_change(vec![a.compute_hash()], 1, "device-2", "c.bin", &sender_signing);
        sender.dag_admit_change(&c, true).unwrap();
        let plan = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![c.compute_hash()],
            pruned: vec![a.compute_hash()],
            blocking_devices: vec![],
        };
        let snapshot = sender.build_compaction_snapshot(&plan).unwrap();
        let checkpoint = Checkpoint::new(group(), plan.checkpoint_frontier.clone(), snapshot.snapshot_hash());
        sender.commit_compaction_snapshot(&checkpoint, &snapshot, &plan.pruned).unwrap();
        let snapshot_bytes = sender.checkpoint_snapshot(&checkpoint.checkpoint_hash()).unwrap().unwrap();

        // Device 1 (receiver): went offline right after admitting a, then
        // made its own local edit b (a -> b) that device 2 never saw.
        let receiver = SyncState::open_in_memory().unwrap();
        receiver.dag_admit_change(&a, true).unwrap();
        let offline_version = file_version(0x11, 4);
        {
            let conn = receiver.pool.get().unwrap();
            crate::dag_store::put_file_version(&conn, "g", &offline_version).unwrap();
        }
        let b = Change::create_signed(
            vec![a.compute_hash()],
            a.lamport,
            crate::change::ChangeAuth::PLACEHOLDER,
            DeviceId("device-1".into()),
            group(),
            vec![Op::Create {
                path: SyncPath("offline.bin".into()),
                version: offline_version.version_hash,
            }],
            &receiver_signing,
        );
        receiver.dag_admit_change(&b, true).unwrap();
        assert_eq!(receiver.dag_group_heads("g").unwrap(), vec![b.compute_hash()]);

        let manifest = SnapshotManifest::new_signed(
            checkpoint,
            vec![c.compute_hash()],
            None,
            DeviceId("device-2".into()),
            &sender_signing,
        )
        .unwrap();

        let emitter = ChangeEmitter::new("device-1", receiver_signing.clone());
        receiver
            .install_rebootstrap_snapshot(&manifest, &snapshot_bytes, Some(&emitter))
            .unwrap();

        // b's original signed hash cannot survive (parents are part of its
        // signed bytes; splicing a new parent onto it is not possible), but
        // its content must survive as a brand-new change parented directly
        // on the new frontier.
        let heads = receiver.dag_group_heads("g").unwrap();
        assert_eq!(heads.len(), 1, "exactly one squashed change should replace the offline branch");
        let squashed_hash = heads[0];
        assert_ne!(
            squashed_hash,
            b.compute_hash(),
            "the original signed change cannot simply be reparented onto the new frontier"
        );
        assert_eq!(receiver.dag_parents_of(&squashed_hash).unwrap(), vec![c.compute_hash()]);

        let squashed = receiver.dag_get_change(&squashed_hash).unwrap().unwrap();
        assert_eq!(
            squashed.ops,
            vec![Op::Create {
                path: SyncPath("offline.bin".into()),
                version: offline_version.version_hash
            }],
            "the shared ancestor's own op must not be re-included -- only the offline-only edit"
        );
        assert!(
            receiver
                .dag_list_unapplied_changes("g")
                .unwrap()
                .iter()
                .any(|change| change.compute_hash() == squashed_hash),
            "the squashed change must be left unapplied for the ordinary reprojection backstop"
        );

        // Survives a restart too.
        let conn = receiver.pool.get().unwrap();
        crate::dag_store::init_dag_schema(&conn).expect(
            "repair on reopen must succeed after squashing an offline-diverged branch onto the \
             new frontier",
        );
    }

    /// Issue B: `change_checkpoints.seq` alone cannot prevent a rollback --
    /// it is reassigned locally by whichever device installs a manifest --
    /// and a bare per-signer counter cannot either (it can diverge across
    /// devices for a perfectly causally-connected lineage, and a fork can
    /// trivially carry a higher count). `SnapshotManifest.previous_
    /// checkpoint_hash` is a signed one-hop hash-chain link, checked as a
    /// genuine lineage proof: reject a manifest that does not directly
    /// extend what is currently installed (whether older, forked, or
    /// skipping ahead), accept the identical checkpoint as a harmless
    /// idempotent re-install, and accept a genuine one-hop forward advance.
    #[test]
    fn install_rebootstrap_snapshot_enforces_one_hop_lineage_continuity() {
        let signing = signing_key(12);

        let sender = SyncState::open_in_memory().unwrap();
        let a = delete_change(vec![], 0, "device-a", "a.bin", &signing);
        sender.dag_admit_change(&a, true).unwrap();
        let b = delete_change(vec![a.compute_hash()], 1, "device-a", "b.bin", &signing);
        sender.dag_admit_change(&b, true).unwrap();
        let plan1 = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![b.compute_hash()],
            pruned: vec![a.compute_hash()],
            blocking_devices: vec![],
        };
        let snapshot1 = sender.build_compaction_snapshot(&plan1).unwrap();
        let checkpoint1 =
            Checkpoint::new(group(), plan1.checkpoint_frontier.clone(), snapshot1.snapshot_hash());
        sender.commit_compaction_snapshot(&checkpoint1, &snapshot1, &plan1.pruned).unwrap();
        let snapshot_bytes1 =
            sender.checkpoint_snapshot(&checkpoint1.checkpoint_hash()).unwrap().unwrap();

        // Sender advances again, on the same lineage: a genuine second
        // compaction whose previous_checkpoint_hash directly names
        // checkpoint1.
        let c = delete_change(vec![b.compute_hash()], 2, "device-a", "c.bin", &signing);
        sender.dag_admit_change(&c, true).unwrap();
        let plan2 = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![c.compute_hash()],
            pruned: vec![b.compute_hash()],
            blocking_devices: vec![],
        };
        let snapshot2 = sender.build_compaction_snapshot(&plan2).unwrap();
        let checkpoint2 =
            Checkpoint::new(group(), plan2.checkpoint_frontier.clone(), snapshot2.snapshot_hash());
        sender.commit_compaction_snapshot(&checkpoint2, &snapshot2, &plan2.pruned).unwrap();
        let snapshot_bytes2 =
            sender.checkpoint_snapshot(&checkpoint2.checkpoint_hash()).unwrap().unwrap();
        assert_eq!(
            sender.history_base_previous_checkpoint_hash("g").unwrap(),
            Some(checkpoint1.checkpoint_hash().0),
            "setup: sender's second checkpoint must record the first as its predecessor"
        );

        let manifest1 = SnapshotManifest::new_signed(
            checkpoint1.clone(),
            vec![b.compute_hash()],
            None,
            DeviceId("device-a".into()),
            &signing,
        )
        .unwrap();
        let manifest2 = SnapshotManifest::new_signed(
            checkpoint2.clone(),
            vec![c.compute_hash()],
            Some(checkpoint1.checkpoint_hash().0),
            DeviceId("device-a".into()),
            &signing,
        )
        .unwrap();

        let receiver = SyncState::open_in_memory().unwrap();
        receiver.dag_admit_change(&a, true).unwrap();
        receiver.dag_admit_change(&b, true).unwrap();

        // A genuine first (bootstrap) install succeeds regardless of what
        // previous_checkpoint_hash claims -- there is nothing installed yet
        // to extend or fork away from.
        receiver.install_rebootstrap_snapshot(&manifest1, &snapshot_bytes1, None).unwrap();
        assert_eq!(receiver.history_base("g").unwrap(), Some(HistoryBase::from_checkpoint(&checkpoint1)));

        // A genuine one-hop forward advance succeeds.
        receiver.dag_admit_change(&c, true).unwrap();
        receiver.install_rebootstrap_snapshot(&manifest2, &snapshot_bytes2, None).unwrap();
        assert_eq!(receiver.history_base("g").unwrap(), Some(HistoryBase::from_checkpoint(&checkpoint2)));

        // Re-installing the now-superseded checkpoint1 is a rollback --
        // refused, state unchanged.
        let error = receiver
            .install_rebootstrap_snapshot(&manifest1, &snapshot_bytes1, None)
            .unwrap_err();
        assert!(
            matches!(error, SyncError::CorruptState(ref m) if m.contains("does not directly extend")),
            "unexpected error: {error:?}"
        );
        assert_eq!(receiver.history_base("g").unwrap(), Some(HistoryBase::from_checkpoint(&checkpoint2)));

        // Re-installing the identical, already-current checkpoint2 is a
        // harmless idempotent re-install.
        receiver.install_rebootstrap_snapshot(&manifest2, &snapshot_bytes2, None).unwrap();
        assert_eq!(receiver.history_base("g").unwrap(), Some(HistoryBase::from_checkpoint(&checkpoint2)));
    }

    /// A manifest whose `previous_checkpoint_hash` does not name the
    /// receiver's actual currently-installed checkpoint -- an unrelated
    /// fork, not a legitimate forward advance or a harmless re-install --
    /// must be refused, even though its own signature and internal
    /// structure are perfectly valid.
    #[test]
    fn install_rebootstrap_snapshot_refuses_an_unrelated_fork() {
        let signing = signing_key(13);

        let sender = SyncState::open_in_memory().unwrap();
        let a = delete_change(vec![], 0, "device-a", "a.bin", &signing);
        sender.dag_admit_change(&a, true).unwrap();
        let b = delete_change(vec![a.compute_hash()], 1, "device-a", "b.bin", &signing);
        sender.dag_admit_change(&b, true).unwrap();
        let plan = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![b.compute_hash()],
            pruned: vec![a.compute_hash()],
            blocking_devices: vec![],
        };
        let snapshot = sender.build_compaction_snapshot(&plan).unwrap();
        let checkpoint = Checkpoint::new(group(), plan.checkpoint_frontier.clone(), snapshot.snapshot_hash());
        sender.commit_compaction_snapshot(&checkpoint, &snapshot, &plan.pruned).unwrap();
        let snapshot_bytes = sender.checkpoint_snapshot(&checkpoint.checkpoint_hash()).unwrap().unwrap();

        // A second, unrelated sender independently produces a DIFFERENT
        // checkpoint for the same group and frontier hash space -- a fork,
        // not the same lineage.
        let other_signing = signing_key(14);
        let other_sender = SyncState::open_in_memory().unwrap();
        let a2 = delete_change(vec![], 0, "device-c", "a2.bin", &other_signing);
        other_sender.dag_admit_change(&a2, true).unwrap();
        let b2 = delete_change(vec![a2.compute_hash()], 1, "device-c", "b2.bin", &other_signing);
        other_sender.dag_admit_change(&b2, true).unwrap();
        let plan2 = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![b2.compute_hash()],
            pruned: vec![a2.compute_hash()],
            blocking_devices: vec![],
        };
        let snapshot2 = other_sender.build_compaction_snapshot(&plan2).unwrap();
        let checkpoint2 =
            Checkpoint::new(group(), plan2.checkpoint_frontier.clone(), snapshot2.snapshot_hash());
        other_sender.commit_compaction_snapshot(&checkpoint2, &snapshot2, &plan2.pruned).unwrap();
        let snapshot_bytes2 =
            other_sender.checkpoint_snapshot(&checkpoint2.checkpoint_hash()).unwrap().unwrap();

        let receiver = SyncState::open_in_memory().unwrap();
        receiver.dag_admit_change(&a, true).unwrap();
        receiver.dag_admit_change(&b, true).unwrap();
        let manifest = SnapshotManifest::new_signed(
            checkpoint,
            vec![b.compute_hash()],
            None,
            DeviceId("device-a".into()),
            &signing,
        )
        .unwrap();
        receiver.install_rebootstrap_snapshot(&manifest, &snapshot_bytes, None).unwrap();

        // The gate fires purely from `group_history_bases` state, before any
        // frontier-reachability walk over local DAG structure -- the
        // receiver need not have admitted the forked sender's history at
        // all for this to be refused. Its previous_checkpoint_hash is None
        // (it's its own sender's genesis), which does not match the
        // receiver's actual current checkpoint either way.
        let forked_manifest = SnapshotManifest::new_signed(
            checkpoint2,
            vec![b2.compute_hash()],
            None,
            DeviceId("device-c".into()),
            &other_signing,
        )
        .unwrap();
        let error = receiver
            .install_rebootstrap_snapshot(&forked_manifest, &snapshot_bytes2, None)
            .unwrap_err();
        assert!(
            matches!(error, SyncError::CorruptState(ref m) if m.contains("does not directly extend")),
            "unexpected error: {error:?}"
        );
    }

    fn file_version(byte: u8, size: u64) -> FileVersion {
        FileVersion::new(
            vec![crate::change::VersionBlock {
                hash: crate::change::BlockHash(vec![byte; 32]),
                size: size as u32,
            }],
            size,
            crate::change::FileMeta {
                mtime_unix_nanos: byte as i64,
                exec_bit: false,
                symlink_target: None,
                record_kind: crate::types::RecordKind::File,
            },
        )
    }

    fn file_record(version: &FileVersion, path: &str) -> FileRecord {
        FileRecord {
            path: path.into(),
            size: version.size,
            mtime_unix_nanos: version.meta.mtime_unix_nanos,
            version: VersionVector::new(),
            blocks: version
                .blocks
                .iter()
                .map(|b| crate::types::BlockInfo { hash: b.hash.0.clone(), offset: 0, size: b.size })
                .collect(),
            deleted: false,
        }
    }

    /// E2E: a real compaction must not strand a still-live materialized
    /// version's block-serving authorization. `v1` is superseded by `v2` but
    /// retained (the built-in version-retention policy keeps it); the only
    /// change that ever admitted `v1` (`change1`) becomes prunable once `v2`'s
    /// change (`change2`) supersedes it. Losing `v1`'s serving authorization
    /// here would make a live, policy-retained version's blocks unservable
    /// purely because compaction ran -- a correctness regression, not merely
    /// a security one.
    #[test]
    fn compaction_preserves_serving_authorization_for_a_live_superseded_version() {
        let emitter = ChangeEmitter::new("device-a", signing_key(9));

        let sender = SyncState::open_in_memory().unwrap();
        let v1 = file_version(1, 3);
        let v2 = file_version(2, 4);
        let change1 = sender
            .upsert_file_emitting_change(
                "g",
                &file_record(&v1, "a.bin"),
                "device-a",
                vec![Op::Create { path: SyncPath("a.bin".into()), version: v1.version_hash }],
                std::slice::from_ref(&v1),
                None,
                &emitter,
            )
            .unwrap();
        let change2 = sender
            .upsert_file_emitting_change(
                "g",
                &file_record(&v2, "a.bin"),
                "device-a",
                vec![Op::Update { path: SyncPath("a.bin".into()), version: v2.version_hash }],
                std::slice::from_ref(&v2),
                None,
                &emitter,
            )
            .unwrap();

        assert!(sender.dag_group_file_version_references_block("g", &[1u8; 32]).unwrap());
        assert!(sender.dag_group_file_version_references_block("g", &[2u8; 32]).unwrap());

        let plan = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![change2],
            pruned: vec![change1],
            blocking_devices: vec![],
        };
        let snapshot = sender.build_compaction_snapshot(&plan).unwrap();
        let checkpoint = Checkpoint::new(group(), plan.checkpoint_frontier.clone(), snapshot.snapshot_hash());
        sender.commit_compaction_snapshot(&checkpoint, &snapshot, &plan.pruned).unwrap();

        // change1 (the only change that ever admitted v1) is gone...
        assert_eq!(sender.dag_parents_of(&change2).unwrap(), Vec::<ChangeHash>::new());
        // ...but both the superseded-and-retained v1 and the current v2 must
        // still be servable: compaction may never turn a live materialized
        // version into an unservable one.
        assert!(
            sender.dag_group_file_version_references_block("g", &[1u8; 32]).unwrap(),
            "a superseded-but-retained version must stay servable after compaction"
        );
        assert!(sender.dag_group_file_version_references_block("g", &[2u8; 32]).unwrap());
    }

    /// A version authorized only via `compacted_file_version_authorization`
    /// under the receiver's *old* HistoryBase must not remain servable after
    /// a re-bootstrap install onto a new HistoryBase that does not retain
    /// it. Before the fix, the install loop only ever added to
    /// `file_versions`/`compacted_file_version_authorization`
    /// (`INSERT OR IGNORE`), so this stale row -- and the block-serving
    /// capability it grants via `group_file_version_references_block`'s
    /// compacted-authorization fallback -- would survive untouched.
    #[test]
    fn install_rebootstrap_snapshot_revokes_stale_compacted_authorization() {
        let signing = signing_key(5);

        let sender = SyncState::open_in_memory().unwrap();
        let a = delete_change(vec![], 0, "device-a", "a.bin", &signing);
        sender.dag_admit_change(&a, true).unwrap();
        let b = delete_change(vec![a.compute_hash()], 1, "device-a", "b.bin", &signing);
        sender.dag_admit_change(&b, true).unwrap();
        let plan = PrunePlan {
            group_id: group(),
            checkpoint_frontier: vec![b.compute_hash()],
            pruned: vec![a.compute_hash()],
            blocking_devices: vec![],
        };
        let snapshot = sender.build_compaction_snapshot(&plan).unwrap();
        let checkpoint = Checkpoint::new(group(), plan.checkpoint_frontier.clone(), snapshot.snapshot_hash());
        sender.commit_compaction_snapshot(&checkpoint, &snapshot, &plan.pruned).unwrap();
        let snapshot_bytes = sender.checkpoint_snapshot(&checkpoint.checkpoint_hash()).unwrap().unwrap();

        // The receiver has already caught up to exactly the incoming
        // frontier (no local descendant needed for this test), plus a
        // version authorized independently of any admitted change --
        // exactly the shape a prior local compaction under a now-superseded
        // HistoryBase would leave behind.
        let receiver = SyncState::open_in_memory().unwrap();
        receiver.dag_admit_change(&a, true).unwrap();
        receiver.dag_admit_change(&b, true).unwrap();
        let stale_version = file_version(0xAB, 7);
        {
            let conn = receiver.pool.get().unwrap();
            crate::dag_store::put_file_version(&conn, "g", &stale_version).unwrap();
            crate::dag_store::record_compacted_file_version_authorization(
                &conn,
                "g",
                &stale_version.version_hash,
            )
            .unwrap();
        }
        assert!(
            receiver.dag_group_file_version_references_block("g", &[0xABu8; 32]).unwrap(),
            "setup: stale version must be servable before install"
        );

        let manifest = SnapshotManifest::new_signed(
            checkpoint,
            vec![b.compute_hash()],
            None,
            DeviceId("device-a".into()),
            &signing,
        )
        .unwrap();
        receiver.install_rebootstrap_snapshot(&manifest, &snapshot_bytes, None).unwrap();

        assert!(
            !receiver.dag_group_file_version_references_block("g", &[0xABu8; 32]).unwrap(),
            "a version authorized only under the old HistoryBase must not survive re-bootstrap"
        );
    }
}
