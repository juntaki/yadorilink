//! R3.3 HistoryBase/snapshot persistence and the production atomic
//! installer (Phase 7D-9D).
//!
//! Moved from `yadorilink-sync-core::index::rebootstrap_store::base` --
//! every function here was already either a plain `&Connection`/
//! `&rusqlite::Transaction` free function or an `impl SyncState` method
//! whose body was *itself* already a `self.database.read(|conn| ..)`/
//! `self.database.write_immediate(|tx| ..)` closure over such a free
//! function's shape; converting the closures into real free functions
//! taking `conn`/`tx` directly required no behavioral change. The one
//! exception, `install_rebootstrap_snapshot`, needs one piece of live
//! `SyncState`-instance state (`local_emission_auth`, an injected signing
//! policy callback) -- that single value is computed by the thin
//! `SyncState::install_rebootstrap_snapshot` wrapper left behind in
//! sync-core, BEFORE the transaction opens, and passed in here as an
//! already-resolved `Option<ChangeAuth>`, exactly the "pre-snapshotted
//! value in, never a live handle" shape this whole initiative's routing
//! rules require.
//!
//! `build_compaction_snapshot`'s current-heads check previously ran as a
//! *separate* `self.database.read` call (via `SyncState::dag_group_heads`)
//! before the snapshot-building read. Folded into the same `conn` here --
//! both are read-only, so this can only make the two reads more mutually
//! consistent (one snapshot instead of two independently-acquired ones),
//! never less.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension};

use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath, VersionHash};
use yadorilink_replica_engine::compaction::{Checkpoint, CheckpointHash, PrunePlan};
use yadorilink_replica_engine::rebootstrap::{HistoryBase, SnapshotManifest};
use yadorilink_replica_engine::rebootstrap_snapshot::{
    BoundaryParentAuth, RebootstrapSnapshot, SnapshotFile, SnapshotVersionState,
};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::dag_store::ChangeEmitter;
use crate::SyncSqliteError;

/// Direct accessor for the six pure-forward `group_history_bases`/
/// `change_checkpoint_snapshots`/`history_boundary_parent_auth` reads and
/// writes below -- migrated off the former `SyncState::history_base`/
/// `history_base_previous_checkpoint_hash`/`checkpoint_snapshot`/
/// `compacted_parent_auth`/`build_compaction_snapshot`/
/// `commit_compaction_snapshot` one-line delegate wrappers (Phase 7D-9F),
/// following the [`crate::HandoffLeaseRepository`] precedent. Opens the
/// pooled connection/`IMMEDIATE` transaction itself instead of taking a raw
/// `&Connection`/`&Transaction` from the caller, so no `rusqlite` type
/// crosses this repository's own public boundary.
///
/// `install_rebootstrap_snapshot` stayed on `SyncState` in
/// `yadorilink-sync-core` -- it needs `self.local_emission_auth(..)`, a
/// live `SyncState`-instance-scoped signing-policy callback, resolved
/// before the transaction opens, so it is `composition`, not a pure
/// forward this repository can serve.
pub struct RebootstrapStoreRepository {
    database: Arc<SyncDatabase>,
}

impl RebootstrapStoreRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Persisted R3.3 history base for a group, if this device has crossed a
    /// compaction/re-bootstrap boundary. `None` is the un-compacted genesis
    /// history, not an error.
    pub fn history_base(&self, group_id: &str) -> Result<Option<HistoryBase>, SyncSqliteError> {
        self.database.read(|conn| history_base(conn, group_id))
    }

    /// See the free function of the same name for the exact contract.
    pub fn history_base_previous_checkpoint_hash(
        &self,
        group_id: &str,
    ) -> Result<Option<[u8; 32]>, SyncSqliteError> {
        self.database
            .read(|conn| history_base_previous_checkpoint_hash(conn, group_id))
    }

    pub fn checkpoint_snapshot(
        &self,
        checkpoint_hash: &CheckpointHash,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.database.read(|conn| checkpoint_snapshot(conn, checkpoint_hash))
    }

    /// See the free function of the same name for the exact contract.
    pub fn compacted_parent_auth(
        &self,
        group_id: &str,
        child_hash: &ChangeHash,
        parent_hash: &ChangeHash,
    ) -> Result<Option<(u64, u64)>, SyncSqliteError> {
        self.database
            .read(|conn| compacted_parent_auth(conn, group_id, child_hash, parent_hash))
    }

    /// Builds the exact snapshot a destructive compaction will commit. See
    /// the free function of the same name for the exact contract.
    pub fn build_compaction_snapshot(
        &self,
        plan: &PrunePlan,
    ) -> Result<RebootstrapSnapshot, SyncSqliteError> {
        self.database.read(|conn| build_compaction_snapshot(conn, plan))
    }

    /// Commits checkpoint snapshot + HistoryBase + boundary authorization
    /// proof and deletes the prefix in one SQLite transaction.
    pub fn commit_compaction_snapshot(
        &self,
        checkpoint: &Checkpoint,
        snapshot: &RebootstrapSnapshot,
        pruned: &[ChangeHash],
    ) -> Result<(), SyncSqliteError> {
        self.database
            .write_immediate(|tx| commit_compaction_snapshot(tx, checkpoint, snapshot, pruned))
    }
}

fn decode_stored_change(bytes: &[u8]) -> Result<Change, SyncSqliteError> {
    Change::from_wire_bytes(bytes).map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "invalid Change in re-bootstrap persistence: {error}"
        ))
    })
}

fn decode_stored_file_version(bytes: &[u8]) -> Result<FileVersion, SyncSqliteError> {
    FileVersion::from_canonical_encoding(bytes).map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "invalid FileVersion in re-bootstrap persistence: {error}"
        ))
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
) -> Result<Option<[u8; 32]>, SyncSqliteError> {
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
                SyncSqliteError::CorruptState(format!(
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

pub fn init_rebootstrap_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(REBOOTSTRAP_SCHEMA)?;
    Ok(())
}

/// Persisted R3.3 history base for a group, if this device has crossed a
/// compaction/re-bootstrap boundary. `None` is the un-compacted genesis
/// history, not an error.
pub fn history_base(
    conn: &Connection,
    group_id: &str,
) -> Result<Option<HistoryBase>, SyncSqliteError> {
    init_rebootstrap_schema(conn)?;
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
                SyncSqliteError::CorruptState(format!(
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
    conn: &Connection,
    group_id: &str,
) -> Result<Option<[u8; 32]>, SyncSqliteError> {
    init_rebootstrap_schema(conn)?;
    read_history_base_previous_checkpoint_hash(conn, group_id)
}

pub fn checkpoint_snapshot(
    conn: &Connection,
    checkpoint_hash: &CheckpointHash,
) -> Result<Option<Vec<u8>>, SyncSqliteError> {
    init_rebootstrap_schema(conn)?;
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
    conn: &Connection,
    group_id: &str,
    child_hash: &ChangeHash,
    parent_hash: &ChangeHash,
) -> Result<Option<(u64, u64)>, SyncSqliteError> {
    init_rebootstrap_schema(conn)?;
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
            return Err(SyncSqliteError::CorruptState(
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
    conn: &Connection,
    plan: &PrunePlan,
) -> Result<RebootstrapSnapshot, SyncSqliteError> {
    let group_id = plan.group_id.as_str();
    init_rebootstrap_schema(conn)?;
    let mut current_heads = crate::dag_store::group_heads(conn, group_id)?;
    current_heads.sort();
    let mut checkpoint_frontier = plan.checkpoint_frontier.clone();
    checkpoint_frontier.sort();
    if current_heads != checkpoint_frontier {
        return Err(SyncSqliteError::CorruptState(format!(
            "refusing compaction for group {group_id}: checkpoint frontier is not the current materialized frontier"
        )));
    }
    if plan.pruned.is_empty() {
        return Err(SyncSqliteError::CorruptState(
            "cannot build a compaction snapshot for an empty prune".into(),
        ));
    }

    let files = read_snapshot_files(conn, group_id)?;

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
        let encoded = crate::dag_store::get_encoded(conn, hash)?.ok_or_else(|| {
            SyncSqliteError::CorruptState(format!(
                "checkpoint frontier change {} is missing while building snapshot",
                hash.to_hex()
            ))
        })?;
        let change = decode_stored_change(&encoded)?;
        if change.group_id.as_str() != group_id {
            return Err(SyncSqliteError::CorruptState(
                "checkpoint frontier contains a foreign-group change".into(),
            ));
        }
        for op in &change.ops {
            if let Some(version_hash) = op_version_hash(op) {
                let version = crate::dag_store::get_file_version(conn, group_id, &version_hash)?
                    .ok_or_else(|| {
                        SyncSqliteError::CorruptState(format!(
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
            let parent_encoded = crate::dag_store::get_encoded(conn, parent_hash)?.ok_or_else(
                || {
                    SyncSqliteError::CorruptState(format!(
                        "pruned checkpoint-boundary parent {} disappeared before \
                         snapshot construction",
                        parent_hash.to_hex()
                    ))
                },
            )?;
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

    Ok(RebootstrapSnapshot::new(
        plan.group_id.clone(),
        files,
        frontier_changes,
        versions.into_values().collect(),
        boundary_parent_auth,
    )?)
}

/// Commits checkpoint snapshot + HistoryBase + boundary authorization proof
/// and deletes the prefix in one SQLite transaction.
pub fn commit_compaction_snapshot(
    tx: &rusqlite::Transaction<'_>,
    checkpoint: &Checkpoint,
    snapshot: &RebootstrapSnapshot,
    pruned: &[ChangeHash],
) -> Result<(), SyncSqliteError> {
    snapshot.validate_against_checkpoint(checkpoint)?;
    init_rebootstrap_schema(tx)?;
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

    crate::dag_store::commit_prune(tx, checkpoint, pruned)?;

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
        crate::dag_store::put_file_version(tx, checkpoint.group_id.as_str(), &version)?;
        crate::dag_store::record_compacted_file_version_authorization(
            tx,
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
                SyncSqliteError::CorruptState(
                    "stored HistoryBase checkpoint_hash is not 32 bytes".into(),
                )
            })
        })
        .transpose()?;
    persist_history_base_and_boundary(tx, checkpoint, snapshot, previous_checkpoint_hash)?;
    Ok(())
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
///
/// `local_auth` is the caller's own already-resolved
/// `local_emission_auth(group_id)` result -- a live, `SyncState`-instance-
/// scoped signing-policy lookup that must run *before* this function (and
/// before the caller's own transaction opens), never inside it. Must be
/// `Some` whenever `local_emitter` is `Some` (the caller's own
/// responsibility; this function only consumes the already-resolved value
/// when an offline branch actually needs re-signing).
pub fn install_rebootstrap_snapshot(
    tx: &rusqlite::Transaction<'_>,
    manifest: &SnapshotManifest,
    snapshot_bytes: &[u8],
    local_emitter: Option<&ChangeEmitter>,
    local_auth: Option<ChangeAuth>,
) -> Result<(), SyncSqliteError> {
    let snapshot = RebootstrapSnapshot::decode(snapshot_bytes)?;
    snapshot.validate_against_checkpoint(&manifest.checkpoint)?;
    if snapshot.group_id != manifest.group_id {
        return Err(SyncSqliteError::CorruptState(
            "re-bootstrap manifest and snapshot group disagree".into(),
        ));
    }

    init_rebootstrap_schema(tx)?;
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
        let is_idempotent_reinstall =
            current_checkpoint_hash.as_slice() == &incoming_checkpoint_hash.0[..];
        let is_direct_advance = manifest
            .previous_checkpoint_hash
            .is_some_and(|hash| hash[..] == current_checkpoint_hash[..]);
        if !is_idempotent_reinstall && !is_direct_advance {
            return Err(SyncSqliteError::CorruptState(format!(
                "re-bootstrap manifest for group {group_id} does not directly extend \
                 (previous_checkpoint_hash does not match) the currently installed \
                 HistoryBase; refusing to roll back, fork, or skip ahead without proof \
                 of continuous lineage"
            )));
        }
    }

    let boundary_parents: HashSet<ChangeHash> =
        snapshot.boundary_parent_auth.iter().map(|edge| edge.parent_hash).collect();
    let reachability =
        retained_descendants_reaching_frontier(tx, group_id, &frontier, &boundary_parents)?;
    if !reachability.offline_branches.is_empty() && local_emitter.is_none() {
        let head = reachability.offline_branches[0].head;
        return Err(SyncSqliteError::CorruptState(format!(
            "local retained head {} does not descend from incoming checkpoint frontier \
             and no local signing key was provided to re-emit its offline edits; \
             refusing to mix HistoryBases",
            head.to_hex()
        )));
    }
    let retained = reachability.retained;
    replace_group_files_from_snapshot(tx, group_id, &snapshot.files)?;

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
            return Err(SyncSqliteError::CorruptState(
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
    tx.execute("DELETE FROM orphan_changes WHERE group_id = ?1", [group_id])?;
    tx.execute("DELETE FROM device_frontier WHERE group_id = ?1", [group_id])?;

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

    install_snapshot_frontier(tx, &manifest.checkpoint, &snapshot)?;

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
        let auth =
            local_auth.expect("checked above: local_auth is Some whenever local_emitter is Some");
        let ops = squash_offline_ops(&branch.chain);
        if ops.is_empty() {
            continue;
        }
        crate::dag_store::emit_local_change_onto(
            tx,
            group_id,
            manifest.checkpoint.frontier.clone(),
            ops,
            auth,
            emitter,
        )?;
    }

    for encoded in &snapshot.file_versions {
        let version = decode_stored_file_version(encoded)?;
        crate::dag_store::put_file_version(tx, group_id, &version)?;
        crate::dag_store::record_compacted_file_version_authorization(
            tx,
            group_id,
            &version.version_hash,
        )?;
    }

    rebuild_change_file_version_relations(tx, group_id)?;
    rebuild_group_heads(tx, group_id)?;

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
                SyncSqliteError::CorruptState(
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
        crate::dag_store::record_compacted_file_version_authorization(tx, group_id, version_hash)?;
    }
    crate::dag_store::sweep_unreferenced_file_versions(tx, group_id)?;

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
        tx,
        &manifest.checkpoint,
        &snapshot,
        manifest.previous_checkpoint_hash,
    )?;
    Ok(())
}

fn read_snapshot_files(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<SnapshotFile>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT path, size, mtime_unix_nanos, blocks_json, deleted, \
                version_seq, state, origin_device_id, record_kind, symlink_target, \
                exec_bit, symlink_out_of_root \
         FROM files WHERE group_id = ?1 ORDER BY path, version_seq",
    )?;
    let rows = stmt.query_map([group_id], |row| {
        let blocks_json: String = row.get(3)?;
        let blocks: Vec<yadorilink_replica_domain::file::BlockInfo> =
            serde_json::from_str(&blocks_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
        let state_text: String = row.get(6)?;
        let state = SnapshotVersionState::from_db_str(&state_text).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown file version state {state_text}"),
                )),
            )
        })?;
        Ok(SnapshotFile {
            record: yadorilink_replica_domain::file::FileRecord {
                path: row.get(0)?,
                size: row.get::<_, i64>(1)? as u64,
                mtime_unix_nanos: row.get(2)?,
                blocks,
                deleted: row.get::<_, i64>(4)? != 0,
            },
            version_seq: row.get(5)?,
            state,
            origin_device_id: row.get(7)?,
            record_kind: yadorilink_replica_domain::file::RecordKind::from_db_str(
                &row.get::<_, String>(8)?,
            ),
            symlink_target: row.get(9)?,
            exec_bit: row.get::<_, i64>(10)? != 0,
            symlink_out_of_root: row.get::<_, i64>(11)? != 0,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

fn persist_history_base_and_boundary(
    conn: &Connection,
    checkpoint: &Checkpoint,
    snapshot: &RebootstrapSnapshot,
    previous_checkpoint_hash: Option<[u8; 32]>,
) -> Result<(), SyncSqliteError> {
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
) -> Result<(), SyncSqliteError> {
    conn.execute("DELETE FROM files WHERE group_id = ?1", [group_id])?;
    for file in files {
        let blocks_json = serde_json::to_string(&file.record.blocks)?;
        let materialization_state =
            if file.state == SnapshotVersionState::Current && !file.record.deleted {
                "placeholder"
            } else {
                "hydrated"
            };
        conn.execute(
            "INSERT INTO files \
             (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
              version_seq, state, origin_device_id, materialization_state, pinned, \
              record_kind, symlink_target, exec_bit, symlink_out_of_root) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, ?12, ?13, ?14)",
            params![
                group_id,
                &file.record.path,
                file.record.size as i64,
                file.record.mtime_unix_nanos,
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
) -> Result<FrontierReachability, SyncSqliteError> {
    let rows: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut stmt =
            conn.prepare("SELECT change_hash, encoded FROM changes WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    if rows.is_empty() {
        return Ok(FrontierReachability { retained: HashSet::new(), offline_branches: Vec::new() });
    }
    let mut changes = HashMap::new();
    for (hash_bytes, encoded) in rows {
        let array: [u8; 32] = hash_bytes.as_slice().try_into().map_err(|_| {
            SyncSqliteError::CorruptState(
                "stored change hash is not 32 bytes during re-bootstrap".into(),
            )
        })?;
        let hash = ChangeHash(array);
        let change = decode_stored_change(&encoded)?;
        if change.compute_hash() != hash {
            return Err(SyncSqliteError::CorruptState(
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
            change.parents.iter().any(|parent| reaches(*parent, frontier, changes, memo, visiting))
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
                if frontier.contains(parent) || memo.get(parent).copied().unwrap_or(false) {
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
        Present { version: VersionHash },
        Deleted,
    }

    let mut state: BTreeMap<String, PathState> = BTreeMap::new();
    for change in chain {
        for op in &change.ops {
            match op {
                Op::Put { path, version, .. } => {
                    state.insert(
                        path.as_str().to_string(),
                        PathState::Present { version: *version },
                    );
                }
                Op::Delete { path } => {
                    state.insert(path.as_str().to_string(), PathState::Deleted);
                }
                Op::Move { from, to, version } => {
                    state.insert(from.as_str().to_string(), PathState::Deleted);
                    state.insert(to.as_str().to_string(), PathState::Present { version: *version });
                }
            }
        }
    }

    // A squashed op's provenance across the squash boundary is not preserved
    // (see this function's own doc comment) -- whatever `PutOrigin` any
    // constituent op carried, the final op here is always `Direct`: a
    // conflict copy's origin (`source_path`/`losing_change`) names a SPECIFIC
    // historical change, which squashing has already collapsed away by
    // construction.
    state
        .into_iter()
        .map(|(path, path_state)| match path_state {
            PathState::Present { version } => {
                Op::Put { path: SyncPath(path), version, origin: PutOrigin::Direct }
            }
            PathState::Deleted => Op::Delete { path: SyncPath(path) },
        })
        .collect()
}

fn install_snapshot_frontier(
    conn: &Connection,
    checkpoint: &Checkpoint,
    snapshot: &RebootstrapSnapshot,
) -> Result<(), SyncSqliteError> {
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
             (change_hash, group_id, device_id, lamport, encoded, applied, authenticated_header) \
             VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
            params![
                &hash.0[..],
                group_id,
                change.device_id.as_str(),
                change.lamport as i64,
                encoded,
                change.authenticated_header_encoding(),
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
        // Records provenance for any `ConflictCopy` puts this frontier change
        // carries, so a later LOCAL edit's idempotency check
        // (`conflict_copy_already_provisioned`) does not needlessly re-derive
        // an obligation this checkpoint already discharged. Deliberately does
        // NOT call `validate_carrier_conflict_copy_ops` here: this change's
        // `ConflictCopy` op may reference a `losing_change` that was itself
        // pruned before this checkpoint, reachable only through
        // `pruned_change_parents`/`boundary_parent_auth` (written just below,
        // AFTER this loop) rather than the live `change_parents` table the
        // frontier-resolution walk uses -- validating here could reject a
        // perfectly legitimate installed change for a change_hash it cannot
        // yet see. The checkpoint/manifest itself is authenticated separately
        // (`SnapshotManifest::new_signed`); this is only a completeness
        // optimization, not a trust boundary.
        crate::dag_store::record_conflict_copy_ops_provenance(conn, group_id, &change)?;
    }

    // Recreate the compact structural proof for direct parents omitted from the
    // snapshot. This is bounded to boundary edges, not the full pruned prefix.
    let checkpoint_hash = checkpoint.checkpoint_hash();
    for edge in &snapshot.boundary_parent_auth {
        // `author_identity`/`authenticated_header` are left NULL here: the
        // compact `BoundaryParentAuth` wire record never carried this
        // ancestor's device id or full signed body to this replica in the
        // first place (only its Lamport/authorization stamp, enough to
        // preserve the causal-clock relation across the snapshot boundary
        // -- see `pruned_changes`'s own column comments for why this is the
        // one legitimate case those columns are absent).
        conn.execute(
            "INSERT OR REPLACE INTO pruned_changes \
             (group_id, change_hash, checkpoint_hash, lamport, encoding_version) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                group_id,
                &edge.parent_hash.0[..],
                &checkpoint_hash.0[..],
                edge.parent_lamport as i64,
                yadorilink_replica_domain::change::PRUNED_STUB_ENCODING_VERSION,
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
) -> Result<(), SyncSqliteError> {
    conn.execute("DELETE FROM change_file_versions WHERE group_id = ?1", [group_id])?;
    let changes: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut stmt =
            conn.prepare("SELECT change_hash, encoded FROM changes WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    for (hash_bytes, encoded) in changes {
        let hash: [u8; 32] = hash_bytes.as_slice().try_into().map_err(|_| {
            SyncSqliteError::CorruptState("stored change hash is not 32 bytes".into())
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

fn rebuild_group_heads(conn: &Connection, group_id: &str) -> Result<(), SyncSqliteError> {
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
        Op::Put { version, .. } | Op::Move { version, .. } => Some(*version),
        Op::Delete { .. } => None,
    }
}
