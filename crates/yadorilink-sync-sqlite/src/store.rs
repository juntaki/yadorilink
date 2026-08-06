//! `SqliteSyncStore`: the shared replica-history reads every caller needs
//! (`yadorilink-replica-engine`'s `ReplicaHistoryPort`, plus
//! `yadorilink-sync-core`'s `LocalMutationStore`/`MaterializationStatePort`
//! delegate here for the same data). One `Arc<SyncDatabase>`, never a
//! second pool/writer-gate of its own -- `pub fn new(database:
//! Arc<SyncDatabase>) -> Self` is the only constructor; there is no `open`.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use rusqlite::{Connection, OptionalExtension};
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::{BlockInfo, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId, VersionHash};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;
use crate::types::{CurrentVersionSnapshot, RetainedVersion, RetainedVersionState};

/// A permanently-rejected hash's `rejected_changes.rules_version` must equal
/// this to be trusted as settled (see `is_change_rejected`'s own doc
/// comment) -- mirrors `yadorilink-sync-core::reserved_namespace::
/// RULES_VERSION`. This crate cannot depend on that crate, so this is a
/// deliberate, narrow constant duplication (not a query/table duplication);
/// if that constant ever changes, this one must change with it.
const RESERVED_NAMESPACE_RULES_VERSION: u32 = 4;

/// Bounds the [`SqliteSyncStore::missing_ancestor_frontier`] walk's visited
/// set, as a latency safeguard against a pathological/adversarial chain
/// shape rather than trusting the DB-row cap alone. Mirrors
/// `yadorilink-sync-core::dag_store::orphan_integrity::ORPHAN_BOUND`.
const ORPHAN_BOUND: usize = 4096;

pub struct SqliteSyncStore {
    database: Arc<SyncDatabase>,
}

impl SqliteSyncStore {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// The group's current non-superseded heads, ascending by hash --
    /// `group_heads` is a materialized index kept in step with `changes`,
    /// not a live query over it. Delegates to `dag_store`'s own
    /// `frontier_index::group_heads` -- the single SQL implementation of
    /// this read, also called directly (same connection/transaction, no
    /// crate-boundary crossing) by `dag_store`'s internal composite
    /// transactions and by `yadorilink-sync-core`'s transaction-bound
    /// callers that need this read to participate in their own already-open
    /// transaction.
    pub fn group_heads(&self, group: &FolderGroupId) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        self.database
            .read::<_, SyncSqliteError>(|conn| crate::dag_store::group_heads(conn, group.as_str()))
    }

    /// A stored change decoded from its persisted bytes.
    pub fn get_change(&self, hash: &ChangeHash) -> Result<Option<Change>, SyncSqliteError> {
        match self.get_encoded(hash)? {
            None => Ok(None),
            Some(bytes) => Change::from_wire_bytes(&bytes)
                .map(Some)
                .map_err(|e| SyncSqliteError::CorruptState(format!("corrupt stored change: {e}"))),
        }
    }

    /// A stored change's raw encoded bytes (canonical + signature), for
    /// serving it onward to another peer without re-signing. Delegates to
    /// `dag_store::retained_history_integrity::get_encoded` -- the single
    /// SQL implementation of this read (see `group_heads`'s doc comment
    /// above for why this is a delegation rather than a second copy of the
    /// query).
    pub fn get_encoded(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| crate::dag_store::get_encoded(conn, hash))
    }

    /// The stored parent edges of a change. Delegates to
    /// `dag_store::retained_history_integrity::parents_of` (see
    /// `group_heads`'s doc comment).
    pub fn parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| crate::dag_store::parents_of(conn, hash))
    }

    /// Whether a change is already present in the admitted store (not the
    /// orphan buffer). Exposed as its own pooled method for
    /// `yadorilink-sync-core`'s `CompactionDagStore` impl (Phase 7D-7.3), so
    /// that caller no longer needs to reach into `dag_store`'s own
    /// connection-scoped `has_change` for a plain existence check. Delegates
    /// to `dag_store::retained_history_integrity::has_change` (see
    /// `group_heads`'s doc comment).
    pub fn has_change(&self, hash: &ChangeHash) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| crate::dag_store::has_change(conn, hash))
    }

    /// Whether a content-addressed file version is present.
    pub fn has_file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let present: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM file_versions WHERE group_id = ?1 AND version_hash = ?2",
                    rusqlite::params![group.as_str(), &hash.0[..]],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(present.is_some())
        })
    }

    /// A stored file version decoded from its canonical bytes -- the block
    /// list, size, and metadata a change op only references by hash.
    pub fn file_version(
        &self,
        group: &FolderGroupId,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let encoded: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT encoded FROM file_versions WHERE group_id = ?1 AND version_hash = ?2",
                    rusqlite::params![group.as_str(), &hash.0[..]],
                    |r| r.get(0),
                )
                .optional()?;
            match encoded {
                Some(bytes) => {
                    let version = FileVersion::from_canonical_encoding(&bytes).map_err(|_| {
                        SyncSqliteError::NotFound("stored file version is corrupt".into())
                    })?;
                    if version.version_hash != *hash {
                        return Err(SyncSqliteError::NotFound(
                            "stored file version hash does not match its key".into(),
                        ));
                    }
                    Ok(Some(version))
                }
                None => Ok(None),
            }
        })
    }

    /// Whether verified bytes for `block_hash` were actually obtained
    /// through `group_id`, independently of any peer-supplied metadata
    /// references.
    pub fn group_has_block_provenance(
        &self,
        group: &FolderGroupId,
        block_hash: &[u8],
    ) -> Result<bool, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM group_block_provenance \
                 WHERE group_id = ?1 AND block_hash = ?2)",
                rusqlite::params![group.as_str(), block_hash],
                |row| row.get(0),
            )?)
        })
    }

    /// The true missing frontier reachable from `roots`, walking through any
    /// buffered orphans in between. A one-level "is this hash known"
    /// check is not enough for a multi-generation orphan chain: an orphan
    /// whose own parent is also missing must surface that deeper parent,
    /// not the orphan itself (the orphan is already held, re-requesting it
    /// would be a no-op; its missing parent is what a peer must still
    /// send). Bounded at `ORPHAN_BOUND` visited hashes as a latency
    /// safeguard against a pathological/adversarial chain shape; if the
    /// bound is hit, falls back to returning `roots` unchanged -- no worse
    /// than a one-level check, just without the deeper discovery.
    pub fn missing_ancestor_frontier(
        &self,
        roots: &[ChangeHash],
    ) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        let roots: Vec<ChangeHash> = roots.to_vec();
        self.database
            .read::<_, SyncSqliteError>(|conn| missing_ancestor_frontier_on_conn(conn, &roots))
    }

    /// spec "Version Listing": every retained version of `path` (current,
    /// superseded, and trashed alike), newest first.
    pub fn list_versions(
        &self,
        group: &FolderGroupId,
        path: &str,
    ) -> Result<Vec<RetainedVersion>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT version_seq, size, mtime_unix_nanos, blocks_json, deleted, state, \
                        origin_device_id, record_kind, symlink_target, exec_bit \
                 FROM files WHERE group_id = ?1 AND path = ?2 ORDER BY version_seq DESC",
            )?;
            let rows = stmt.query_map(rusqlite::params![group.as_str(), path], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, Option<Vec<u8>>>(8)?,
                    r.get::<_, i64>(9)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (
                    version_seq,
                    size,
                    mtime_unix_nanos,
                    blocks_json,
                    deleted,
                    state,
                    origin_device_id,
                    record_kind,
                    symlink_target,
                    exec_bit,
                ) = row?;
                let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
                    SyncSqliteError::CorruptState(format!(
                        "stored block list for {path} is corrupt: {error}"
                    ))
                })?;
                out.push(RetainedVersion {
                    path: path.to_string(),
                    version_seq,
                    size,
                    mtime_unix_nanos,
                    blocks,
                    deleted: deleted != 0,
                    state: retained_version_state_from_db_str(&state)?,
                    origin_device_id,
                    record_kind: RecordKind::from_db_str(&record_kind),
                    symlink_target,
                    exec_bit: exec_bit != 0,
                });
            }
            Ok(out)
        })
    }

    /// The `state = 'current'` row of a file, read as one atomic statement.
    pub fn get_current_version_record(
        &self,
        group: &FolderGroupId,
        path: &str,
    ) -> Result<Option<CurrentVersionSnapshot>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            #[allow(clippy::type_complexity)]
            let row: Option<(u64, i64, String, i64, String, Option<Vec<u8>>, i64)> = conn
                .query_row(
                    "SELECT size, mtime_unix_nanos, blocks_json, deleted, record_kind, \
                            symlink_target, exec_bit \
                     FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![group.as_str(), path],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                        ))
                    },
                )
                .optional()?;
            row.map(|(size, mtime, blocks_json, deleted, record_kind, symlink_target, exec_bit)| {
                let blocks: Vec<BlockInfo> = serde_json::from_str(&blocks_json).map_err(|error| {
                    SyncSqliteError::CorruptState(format!(
                        "stored block list for current version of {path} is corrupt: {error}"
                    ))
                })?;
                Ok(CurrentVersionSnapshot {
                    blocks,
                    size,
                    mtime_unix_nanos: mtime,
                    deleted: deleted != 0,
                    record_kind: RecordKind::from_db_str(&record_kind),
                    symlink_target,
                    exec_bit: exec_bit != 0,
                })
            })
            .transpose()
        })
    }

    // --- `&str`-group-id / domain-type convenience wrappers ---
    //
    // The methods above are keyed by `&FolderGroupId` and return this
    // crate's own row types (`RetainedVersion`/`CurrentVersionSnapshot`),
    // matching `dag_store`'s and this crate's own internal callers (e.g.
    // `replica_history.rs`). The ten wrappers below exist for callers that
    // used to reach these reads only through `yadorilink-sync-core::SyncState`'s
    // deleted delegate methods of the same names (Phase 7D-9F) -- each is a
    // pure `&str` -> `FolderGroupId` construction plus, for the two whose
    // result type differs, a `.into()`/`.map(...)` conversion into
    // `yadorilink_replica_domain::session_state::{VersionRecord,
    // CurrentVersionRecord}` (the `From` impls in `crate::types` already
    // exist for exactly this). Centralizing the translation here, not at
    // every caller, is the point: every caller gets the exact same
    // `&str`-keyed, domain-typed call shape the deleted `SyncState` methods
    // used to provide. Named with a `dag_`/`dag_get_current_version_record`/
    // `dag_list_versions` prefix specifically to avoid colliding with the
    // `&FolderGroupId`-keyed methods above, not because these are DAG-only
    // reads (`dag_get_current_version_record`/`dag_list_versions` are
    // file-index reads, kept in this group only for naming symmetry with
    // their `SyncState`-era names).
    pub fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        self.group_heads(&FolderGroupId(group_id.to_string()))
    }

    pub fn dag_missing_ancestor_frontier(
        &self,
        roots: impl IntoIterator<Item = ChangeHash>,
    ) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        let roots: Vec<ChangeHash> = roots.into_iter().collect();
        self.missing_ancestor_frontier(&roots)
    }

    pub fn dag_get_change(&self, hash: &ChangeHash) -> Result<Option<Change>, SyncSqliteError> {
        self.get_change(hash)
    }

    pub fn dag_get_encoded(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.get_encoded(hash)
    }

    pub fn dag_has_file_version(
        &self,
        group_id: &str,
        hash: &VersionHash,
    ) -> Result<bool, SyncSqliteError> {
        self.has_file_version(&FolderGroupId(group_id.to_string()), hash)
    }

    pub fn dag_get_file_version(
        &self,
        group_id: &str,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, SyncSqliteError> {
        self.file_version(&FolderGroupId(group_id.to_string()), hash)
    }

    pub fn dag_group_has_block_provenance(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, SyncSqliteError> {
        self.group_has_block_provenance(&FolderGroupId(group_id.to_string()), block_hash)
    }

    pub fn dag_parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        self.parents_of(hash)
    }

    pub fn dag_get_current_version_record(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<yadorilink_replica_domain::session_state::CurrentVersionRecord>, SyncSqliteError>
    {
        Ok(self
            .get_current_version_record(&FolderGroupId(group_id.to_string()), path)?
            .map(Into::into))
    }

    pub fn dag_list_versions(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<yadorilink_replica_domain::session_state::VersionRecord>, SyncSqliteError> {
        Ok(self
            .list_versions(&FolderGroupId(group_id.to_string()), path)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Replaces `device`'s acknowledged frontier for `group` wholesale --
    /// delete then per-head insert, in one transaction, so a reader never
    /// observes a partially-rewritten frontier. `frontier` is stored
    /// exactly as given; normalizing it (sort/dedup) is the caller's job,
    /// not this store's -- see `yadorilink-sync-core::compaction::
    /// record_acknowledged_frontier`, which normalizes then calls this.
    /// Delegates to `dag_store::frontier_index::set_device_frontier` -- the
    /// single SQL implementation of this write (see `group_heads`'s doc
    /// comment above for why this is a delegation rather than a second copy
    /// of the query).
    pub fn set_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &yadorilink_replica_domain::ids::DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::dag_store::set_device_frontier(tx, group.as_str(), device.as_str(), frontier)
        })
    }

    /// `device`'s most recently acknowledged frontier for `group`, ascending
    /// by hash. Empty if the device has never reported one. Delegates to
    /// `dag_store::frontier_index::get_device_frontier` (see
    /// `group_heads`'s doc comment).
    pub fn get_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &yadorilink_replica_domain::ids::DeviceId,
    ) -> Result<Vec<ChangeHash>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            crate::dag_store::get_device_frontier(conn, group.as_str(), device.as_str())
        })
    }

    /// Clears `device`'s acknowledged frontier for `group` entirely -- used
    /// when a device is removed from a group and its frontier should no
    /// longer hold anything back. Delegates to
    /// `dag_store::frontier_index::remove_device_frontier` (see
    /// `group_heads`'s doc comment).
    pub fn remove_device_frontier(
        &self,
        group: &FolderGroupId,
        device: &yadorilink_replica_domain::ids::DeviceId,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            crate::dag_store::remove_device_frontier(tx, group.as_str(), device.as_str())
        })
    }
}

/// Whether `hash` is durably recorded as a permanent rejection under the
/// current reserved-namespace rules. A row stamped with an older rules
/// version is deliberately not trusted as settled -- this returns `false`
/// for it, exactly as if the hash had never been rejected, so the caller's
/// normal "still missing" handling drives a fresh re-request and
/// re-evaluation under the current rules.
fn is_change_rejected(conn: &Connection, hash: &ChangeHash) -> Result<bool, SyncSqliteError> {
    let stamped_version: Option<u32> = conn
        .query_row(
            "SELECT rules_version FROM rejected_changes WHERE change_hash = ?1",
            [&hash.0[..]],
            |r| r.get(0),
        )
        .optional()?;
    Ok(stamped_version == Some(RESERVED_NAMESPACE_RULES_VERSION))
}

fn missing_ancestor_frontier_on_conn(
    conn: &Connection,
    roots: &[ChangeHash],
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut missing = Vec::new();
    let mut visited: HashSet<ChangeHash> = HashSet::new();
    let mut queue: VecDeque<ChangeHash> = VecDeque::new();
    for root in roots {
        if visited.insert(*root) {
            queue.push_back(*root);
        }
    }
    while let Some(hash) = queue.pop_front() {
        if visited.len() > ORPHAN_BOUND {
            tracing::warn!(
                "missing-ancestor-frontier walk exceeded ORPHAN_BOUND visited hashes; \
                 falling back to re-requesting the original roots directly"
            );
            return Ok(roots.to_vec());
        }
        if crate::dag_store::has_change(conn, &hash)? {
            continue;
        }
        if is_change_rejected(conn, &hash)? {
            continue;
        }
        let is_buffered: Option<i64> = conn
            .query_row("SELECT 1 FROM orphan_changes WHERE change_hash = ?1", [&hash.0[..]], |r| {
                r.get(0)
            })
            .optional()?;
        if is_buffered.is_none() {
            missing.push(hash);
            continue;
        }
        let parents: Vec<Vec<u8>> = {
            let mut stmt =
                conn.prepare("SELECT parent_hash FROM change_parents WHERE child_hash = ?1")?;
            let rows = stmt.query_map([&hash.0[..]], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for parent_blob in parents {
            let parent_hash = hash_from_blob(parent_blob)?;
            if visited.insert(parent_hash) {
                queue.push_back(parent_hash);
            }
        }
    }
    Ok(missing)
}

fn hash_from_blob(v: Vec<u8>) -> Result<ChangeHash, SyncSqliteError> {
    let array: [u8; 32] = v
        .try_into()
        .map_err(|_| SyncSqliteError::NotFound("change hash column is not 32 bytes".into()))?;
    Ok(ChangeHash(array))
}

fn retained_version_state_from_db_str(s: &str) -> Result<RetainedVersionState, SyncSqliteError> {
    match s {
        "current" => Ok(RetainedVersionState::Current),
        "superseded" => Ok(RetainedVersionState::Superseded),
        "trashed" => Ok(RetainedVersionState::Trashed),
        other => Err(SyncSqliteError::CorruptState(format!(
            "unknown files.state value {other:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use yadorilink_sqlite_runtime::DatabaseError;

    use super::*;

    /// Minimal stand-in for the tables these reads need -- not this
    /// crate's real schema (item 3 doesn't move schema ownership, only
    /// reads), just enough shape for these tests to exercise real SQL.
    fn test_schema(conn: &Connection) -> Result<(), DatabaseError> {
        conn.execute_batch(
            "CREATE TABLE changes (change_hash BLOB PRIMARY KEY, group_id TEXT NOT NULL, encoded BLOB NOT NULL);
             CREATE TABLE change_parents (child_hash BLOB NOT NULL, parent_hash BLOB NOT NULL);
             CREATE TABLE group_heads (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
             CREATE TABLE orphan_changes (change_hash BLOB PRIMARY KEY);
             CREATE TABLE rejected_changes (change_hash BLOB PRIMARY KEY, rules_version INTEGER NOT NULL);
             CREATE TABLE file_versions (group_id TEXT NOT NULL, version_hash BLOB NOT NULL, encoded BLOB NOT NULL);
             CREATE TABLE group_block_provenance (group_id TEXT NOT NULL, block_hash BLOB NOT NULL);
             CREATE TABLE device_frontier (group_id TEXT NOT NULL, device_id TEXT NOT NULL, change_hash BLOB NOT NULL);
             CREATE TABLE files (
                 group_id TEXT NOT NULL, path TEXT NOT NULL, version_seq INTEGER NOT NULL,
                 size INTEGER NOT NULL, mtime_unix_nanos INTEGER NOT NULL, blocks_json TEXT NOT NULL,
                 deleted INTEGER NOT NULL, state TEXT NOT NULL, origin_device_id TEXT,
                 record_kind TEXT NOT NULL, symlink_target BLOB, exec_bit INTEGER NOT NULL
             );",
        )?;
        Ok(())
    }

    fn open_test_store() -> SqliteSyncStore {
        let database =
            Arc::new(SyncDatabase::open_in_memory(test_schema).expect("open in-memory db"));
        SqliteSyncStore::new(database)
    }

    fn hash(byte: u8) -> ChangeHash {
        ChangeHash([byte; 32])
    }

    fn insert_change(store: &SqliteSyncStore, group: &str, h: ChangeHash, encoded: &[u8]) {
        store
            .database
            .write::<_, SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT INTO changes (change_hash, group_id, encoded) VALUES (?1, ?2, ?3)",
                    rusqlite::params![&h.0[..], group, encoded],
                )?;
                Ok(())
            })
            .expect("insert change");
    }

    fn insert_parent_edge(store: &SqliteSyncStore, child: ChangeHash, parent: ChangeHash) {
        store
            .database
            .write::<_, SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
                    rusqlite::params![&child.0[..], &parent.0[..]],
                )?;
                Ok(())
            })
            .expect("insert parent edge");
    }

    fn insert_group_head(store: &SqliteSyncStore, group: &str, h: ChangeHash) {
        store
            .database
            .write::<_, SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT INTO group_heads (group_id, change_hash) VALUES (?1, ?2)",
                    rusqlite::params![group, &h.0[..]],
                )?;
                Ok(())
            })
            .expect("insert group head");
    }

    #[test]
    fn group_heads_is_empty_for_an_unknown_group() {
        let store = open_test_store();
        let heads = store.group_heads(&FolderGroupId("group-1".into())).expect("group_heads");
        assert!(heads.is_empty());
    }

    #[test]
    fn group_heads_returns_multiple_heads_in_a_stable_hash_order() {
        let store = open_test_store();
        // Inserted out of order; the query itself orders by change_hash, so
        // the result must come back sorted regardless of insertion order.
        insert_group_head(&store, "group-1", hash(3));
        insert_group_head(&store, "group-1", hash(1));
        insert_group_head(&store, "group-1", hash(2));

        let heads = store.group_heads(&FolderGroupId("group-1".into())).expect("group_heads");
        assert_eq!(heads, vec![hash(1), hash(2), hash(3)]);

        // Repeating the read must produce the identical order -- not just
        // "some" order that happens to be sorted once.
        let heads_again = store.group_heads(&FolderGroupId("group-1".into())).expect("group_heads");
        assert_eq!(heads, heads_again);
    }

    #[test]
    fn parents_of_returns_every_recorded_parent_edge() {
        let store = open_test_store();
        insert_parent_edge(&store, hash(10), hash(1));
        insert_parent_edge(&store, hash(10), hash(2));

        let mut parents = store.parents_of(&hash(10)).expect("parents_of");
        parents.sort();
        assert_eq!(parents, vec![hash(1), hash(2)]);
        assert!(store.parents_of(&hash(1)).expect("parents_of").is_empty());
    }

    #[test]
    fn get_encoded_round_trips_the_exact_stored_bytes() {
        let store = open_test_store();
        let encoded = b"canonical-bytes-plus-signature".to_vec();
        insert_change(&store, "group-1", hash(1), &encoded);

        let read_back = store.get_encoded(&hash(1)).expect("get_encoded").expect("present");
        assert_eq!(read_back, encoded);
        assert!(store.get_encoded(&hash(99)).expect("get_encoded").is_none());
    }

    #[test]
    fn missing_ancestor_frontier_of_an_unknown_hash_is_itself() {
        let store = open_test_store();
        let missing = store.missing_ancestor_frontier(&[hash(1)]).expect("missing_ancestor_frontier");
        assert_eq!(missing, vec![hash(1)]);
    }

    #[test]
    fn missing_ancestor_frontier_does_not_treat_a_rejected_change_as_missing() {
        let store = open_test_store();
        store
            .database
            .write::<_, SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT INTO rejected_changes (change_hash, rules_version) VALUES (?1, ?2)",
                    rusqlite::params![&hash(1).0[..], RESERVED_NAMESPACE_RULES_VERSION],
                )?;
                Ok(())
            })
            .expect("insert rejected change");

        let missing = store.missing_ancestor_frontier(&[hash(1)]).expect("missing_ancestor_frontier");
        assert!(missing.is_empty(), "a permanently-rejected hash must not be reported as missing");
    }

    #[test]
    fn missing_ancestor_frontier_walks_through_a_buffered_orphan_to_its_missing_parent() {
        let store = open_test_store();
        // hash(1) is buffered as an orphan whose recorded parent, hash(2),
        // is itself unknown -- the walk must surface hash(2), not hash(1)
        // (hash(1) is already held; re-requesting it would be a no-op).
        store
            .database
            .write::<_, SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT INTO orphan_changes (change_hash) VALUES (?1)",
                    [&hash(1).0[..]],
                )?;
                Ok(())
            })
            .expect("insert orphan");
        insert_parent_edge(&store, hash(1), hash(2));

        let missing = store.missing_ancestor_frontier(&[hash(1)]).expect("missing_ancestor_frontier");
        assert_eq!(missing, vec![hash(2)]);
    }

    #[test]
    fn missing_ancestor_frontier_falls_back_to_roots_when_orphan_bound_is_exceeded() {
        let store = open_test_store();
        // A chain of buffered orphans longer than ORPHAN_BOUND, each
        // pointing at the next as its sole parent (32-byte hashes distinct
        // by their first 4 bytes, a counter) -- the walk must give up and
        // return the original root unchanged, not partially-walked results
        // or an error.
        let hash_for = |i: u32| -> ChangeHash {
            let mut bytes = [0u8; 32];
            bytes[0..4].copy_from_slice(&i.to_le_bytes());
            ChangeHash(bytes)
        };
        store
            .database
            .write::<_, SyncSqliteError>(|conn| {
                for i in 0..=(ORPHAN_BOUND as u32 + 1) {
                    let child = hash_for(i);
                    conn.execute(
                        "INSERT INTO orphan_changes (change_hash) VALUES (?1)",
                        [&child.0[..]],
                    )?;
                    let parent = hash_for(i + 1);
                    conn.execute(
                        "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
                        rusqlite::params![&child.0[..], &parent.0[..]],
                    )?;
                }
                Ok(())
            })
            .expect("insert long orphan chain");
        let root = hash_for(0);

        let missing =
            store.missing_ancestor_frontier(&[root]).expect("missing_ancestor_frontier");
        assert_eq!(
            missing,
            vec![root],
            "exceeding ORPHAN_BOUND must fall back to the original roots unchanged"
        );
    }

    #[test]
    fn list_versions_orders_newest_first_and_preserves_metadata() {
        let store = open_test_store();
        store
            .database
            .write::<_, SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT INTO files (group_id, path, version_seq, size, mtime_unix_nanos, \
                     blocks_json, deleted, state, origin_device_id, record_kind, symlink_target, exec_bit) \
                     VALUES ('group-1', 'a.txt', 1, 10, 100, '[]', 0, 'superseded', 'device-a', 'file', NULL, 0)",
                    [],
                )?;
                conn.execute(
                    "INSERT INTO files (group_id, path, version_seq, size, mtime_unix_nanos, \
                     blocks_json, deleted, state, origin_device_id, record_kind, symlink_target, exec_bit) \
                     VALUES ('group-1', 'a.txt', 2, 20, 200, '[]', 0, 'current', 'device-b', 'file', NULL, 1)",
                    [],
                )?;
                Ok(())
            })
            .expect("insert version rows");

        let versions = store
            .list_versions(&FolderGroupId("group-1".into()), "a.txt")
            .expect("list_versions");
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version_seq, 2, "newest (highest version_seq) must come first");
        assert_eq!(versions[0].state, RetainedVersionState::Current);
        assert_eq!(versions[0].origin_device_id.as_deref(), Some("device-b"));
        assert!(versions[0].exec_bit);
        assert_eq!(versions[1].version_seq, 1);
        assert_eq!(versions[1].state, RetainedVersionState::Superseded);
    }

    #[test]
    fn get_current_version_record_distinguishes_missing_from_corrupt() {
        let store = open_test_store();
        let group = FolderGroupId("group-1".into());
        assert!(
            store.get_current_version_record(&group, "missing.txt").expect("query").is_none(),
            "no row at all must read as None, not an error"
        );

        store
            .database
            .write::<_, SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT INTO files (group_id, path, version_seq, size, mtime_unix_nanos, \
                     blocks_json, deleted, state, origin_device_id, record_kind, symlink_target, exec_bit) \
                     VALUES ('group-1', 'corrupt.txt', 1, 1, 1, 'not-json', 0, 'current', NULL, 'file', NULL, 0)",
                    [],
                )?;
                Ok(())
            })
            .expect("insert corrupt row");
        let result = store.get_current_version_record(&group, "corrupt.txt");
        assert!(result.is_err(), "an unparseable blocks_json column must fail closed, not default to empty");
    }

    #[test]
    fn device_frontier_round_trips_and_replaces_wholesale() {
        let store = open_test_store();
        let group = FolderGroupId("group-1".into());
        let device = yadorilink_replica_domain::ids::DeviceId("device-a".into());

        assert!(store.get_device_frontier(&group, &device).expect("read").is_empty());

        store
            .set_device_frontier(&group, &device, &[hash(2), hash(1)])
            .expect("set frontier");
        assert_eq!(
            store.get_device_frontier(&group, &device).expect("read"),
            vec![hash(1), hash(2)],
            "read must come back ascending by hash regardless of set order"
        );

        // A second set must replace, not accumulate.
        store.set_device_frontier(&group, &device, &[hash(3)]).expect("replace frontier");
        assert_eq!(store.get_device_frontier(&group, &device).expect("read"), vec![hash(3)]);

        store.remove_device_frontier(&group, &device).expect("remove frontier");
        assert!(store.get_device_frontier(&group, &device).expect("read").is_empty());
    }
}
