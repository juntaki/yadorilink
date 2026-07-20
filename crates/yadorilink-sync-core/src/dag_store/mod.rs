//! Persistence for the change-history DAG, stored in the same SQLite
//! database as the file index.
//!
//! Every function here takes a plain `&Connection`. A `rusqlite::Transaction`
//! dereferences to `Connection`, so passing `&tx` runs the operation inside
//! that transaction — this is what lets a local mutation append its change
//! and mutate the file index atomically, in one commit. Reads take the same
//! `&Connection` so callers can query heads/ancestry either standalone or
//! inside a write transaction.
//!
//! This module is a thin orchestration layer over five submodules, each
//! owning one derived structure and re-verifying it against the signed
//! canonical `Change`/`Checkpoint` bytes rather than trusting it at face
//! value -- the split exists so a gap in any one of them (as several were,
//! found by the `dag_*_integrity_red.rs` integration tests) is caught by
//! that structure's own `repair`/read path, not lost in one large function
//! that touches every table at once:
//! - [`retained_history_integrity`] — `changes` (durable, fail-closed) and
//!   the `change_parents` ancestry index derived from it.
//! - [`orphan_integrity`] — `orphan_changes`, a bounded, best-effort holding
//!   buffer (drop-on-inconsistency, never fail-closed).
//! - [`frontier_index`] — `group_heads` and `device_frontier`.
//! - [`serving_authorization_index`] — `file_versions`, the
//!   `change_file_versions` block-serving authorization boundary, and
//!   `group_block_provenance`.
//! - [`checkpoint_store`] — `change_checkpoints`, condensed pruned prefixes.
//!
//! What stays here: schema creation/repair orchestration
//! ([`init_dag_schema`]), and the operations that inherently cross more than
//! one of those structures in a single atomic step
//! ([`admit_change`]/[`emit_local_change`]/[`commit_prune`]).

mod checkpoint_store;
mod frontier_index;
mod orphan_integrity;
mod retained_history_integrity;
mod serving_authorization_index;

pub use checkpoint_store::latest_checkpoint;
pub use frontier_index::{
    get_device_frontier, group_heads, max_parent_lamport, remove_device_frontier,
    set_device_frontier,
};
pub use orphan_integrity::{promote_orphans, ORPHAN_BOUND};
pub use retained_history_integrity::{
    get_encoded, group_history_paths, has_all_parents, has_change, is_ancestor, lamport_of,
    list_unapplied, mark_applied, parents_of,
};
pub(crate) use serving_authorization_index::sweep_unreferenced_file_versions;
pub use serving_authorization_index::{
    get_file_version, group_file_version_references_block, group_has_block_provenance,
    has_file_version, put_file_version, record_compacted_file_version_authorization,
    record_group_block_provenance,
};

use rusqlite::Connection;

#[cfg(test)]
use crate::change::FileVersion;
#[cfg(test)]
use orphan_integrity::insert_orphan;
#[cfg(test)]
use retained_history_integrity::append_change;

use crate::change::{Change, ChangeAuth, ChangeHash, DeviceId, FolderGroupId, Op};
use crate::error::SyncError;

/// Outcome of admitting a verified change from a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitOutcome {
    /// The change's ancestry was complete; it (and any orphans it unblocked)
    /// were inserted into `changes`.
    Applied,
    /// The change's parents are not all present yet; it is held in the
    /// bounded orphan buffer until they arrive.
    Orphaned,
}

/// The full result of admitting a verified change: its outcome plus the hashes
/// of every change that actually landed in `changes` as a side-effect of this
/// admission. `newly_admitted` is the current change followed by every orphan
/// its arrival unblocked, in the order they were appended. It is empty for
/// `Orphaned`.
///
/// The caller needs the promoted-orphan hashes, not just the current one: when
/// a child change arrives before its parent it is buffered, and the parent's
/// later admission both applies the parent AND promotes the child. Both changes
/// become durable in the same call, so both must have their paths projected and
/// their `applied` flag gated in the same batch — otherwise a promoted orphan's
/// paths would not materialize until the periodic reprojection backstop runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitResult {
    pub outcome: AdmitOutcome,
    pub newly_admitted: Vec<ChangeHash>,
}

/// The material a device needs to sign the changes it originates: its own
/// id and its Ed25519 signing key. Held separately from the store so the
/// store never touches secret key material.
pub struct ChangeEmitter {
    device_id: String,
    signing_key: ed25519_dalek::SigningKey,
}

impl ChangeEmitter {
    pub fn new(device_id: impl Into<String>, signing_key: ed25519_dalek::SigningKey) -> Self {
        Self { device_id: device_id.into(), signing_key }
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

/// Creates the DAG tables if they do not exist. New tables only, so — like
/// the index's own `group_policy_watermark` — a
/// bare `CREATE TABLE IF NOT EXISTS` is the whole migration.
pub fn init_dag_schema(conn: &Connection) -> Result<(), SyncError> {
    // v2 keyed versions by hash alone and attached one first-writer group.
    // Rebuild it with group ownership in the primary key before the regular
    // idempotent DDL runs. This preserves every existing row while allowing
    // identical content to be referenced independently by multiple groups.
    let legacy_file_versions =
        conn.prepare("PRAGMA table_info(file_versions)").and_then(|mut stmt| {
            let rows =
                stmt.query_map([], |row| Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?)))?;
            rows.collect::<Result<Vec<_>, _>>()
        })?;
    if legacy_file_versions.iter().any(|(name, pk)| name == "version_hash" && *pk == 1)
        && !legacy_file_versions.iter().any(|(name, pk)| name == "group_id" && *pk > 0)
    {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(
            r#"
            ALTER TABLE file_versions RENAME TO file_versions_v2;
            CREATE TABLE file_versions (
                version_hash BLOB NOT NULL,
                group_id     TEXT NOT NULL,
                encoded      BLOB NOT NULL,
                PRIMARY KEY (group_id, version_hash)
            );
            INSERT INTO file_versions (version_hash, group_id, encoded)
                SELECT version_hash, group_id, encoded FROM file_versions_v2;
            DROP TABLE file_versions_v2;
            CREATE TABLE IF NOT EXISTS change_file_versions (
                group_id     TEXT NOT NULL,
                change_hash  BLOB NOT NULL,
                version_hash BLOB NOT NULL,
                PRIMARY KEY (group_id, change_hash, version_hash)
            );
            "#,
        )?;

        // A v2 row recorded only the first group that stored a global
        // version, even though retained Changes in other groups could
        // legally reference the same hash. Reconstruct cross-group ownership
        // from the authoritative retained history in the same transaction as
        // the shape change itself: missing or corrupt history rolls back the
        // whole conversion rather than committing a partially-converted,
        // unusable table shape. (A database that already carries this shape
        // from an earlier, incomplete conversion — or that lost ownership
        // some other way, e.g. a promote-then-crash race — never enters this
        // `if`; it is instead repaired by the unconditional
        // `retained_history_integrity::repair`/`orphan_integrity::repair` pass
        // below, which also covers `orphan_changes`.)
        let admitted_changes: Vec<Vec<u8>> = {
            let mut stmt = tx.prepare("SELECT encoded FROM changes")?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for encoded in admitted_changes {
            let change = Change::from_wire_bytes(&encoded).map_err(|error| {
                SyncError::CorruptState(format!(
                    "cannot migrate v2 file versions: retained change is corrupt: {error}"
                ))
            })?;
            serving_authorization_index::repair_change_file_versions(&tx, &change, true)?;
        }
        tx.commit()?;
    }
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS changes (
            change_hash BLOB PRIMARY KEY,
            group_id    TEXT NOT NULL,
            device_id   TEXT NOT NULL,
            lamport     INTEGER NOT NULL,
            encoded     BLOB NOT NULL,
            applied     INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS changes_by_group ON changes(group_id);

        CREATE TABLE IF NOT EXISTS change_parents (
            child_hash  BLOB NOT NULL,
            parent_hash BLOB NOT NULL,
            PRIMARY KEY (child_hash, parent_hash)
        );
        CREATE INDEX IF NOT EXISTS change_parents_by_parent
            ON change_parents(parent_hash);

        CREATE TABLE IF NOT EXISTS group_heads (
            group_id    TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, change_hash)
        );

        CREATE TABLE IF NOT EXISTS device_frontier (
            group_id    TEXT NOT NULL,
            device_id   TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, device_id, change_hash)
        );

        CREATE TABLE IF NOT EXISTS orphan_changes (
            change_hash  BLOB PRIMARY KEY,
            group_id     TEXT NOT NULL,
            device_id    TEXT NOT NULL,
            lamport      INTEGER NOT NULL,
            encoded      BLOB NOT NULL,
            applied      INTEGER NOT NULL,
            received_seq INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS file_versions (
            version_hash BLOB NOT NULL,
            group_id     TEXT NOT NULL,
            encoded      BLOB NOT NULL,
            PRIMARY KEY (group_id, version_hash)
        );
        CREATE INDEX IF NOT EXISTS file_versions_by_group ON file_versions(group_id);

        CREATE TABLE IF NOT EXISTS change_file_versions (
            group_id     TEXT NOT NULL,
            change_hash  BLOB NOT NULL,
            version_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, change_hash, version_hash)
        );
        CREATE INDEX IF NOT EXISTS change_file_versions_by_version
            ON change_file_versions(group_id, version_hash);

        -- Physical blocks remain globally content-addressed and deduplicated,
        -- while this table records the groups through which this device has
        -- actually obtained the verified bytes.  FileVersion metadata alone
        -- must never create one of these rows.
        CREATE TABLE IF NOT EXISTS group_block_provenance (
            group_id   TEXT NOT NULL,
            block_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, block_hash)
        );

        -- A version's `change_file_versions` justification is lost the moment
        -- its only referencing change is compacted away, even when the
        -- version itself is still a live (current or retained superseded)
        -- row in the group's materialized file index. This table is that
        -- justification's compaction-surviving analog: the re-bootstrap
        -- snapshot layer records one row per version it re-persisted from
        -- live index state, so `group_file_version_references_block` never
        -- has to treat "the admitting change was pruned" as "this device is
        -- no longer authorized to serve it".
        CREATE TABLE IF NOT EXISTS compacted_file_version_authorization (
            group_id     TEXT NOT NULL,
            version_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, version_hash)
        );
        "#,
    )?;
    retained_history_integrity::repair(conn)?;
    orphan_integrity::repair(conn)?;
    frontier_index::repair(conn)?;
    // The checkpoint table is created in the same step as the other DAG
    // tables so the whole change-history schema is provisioned by one call and
    // in one order; the DDL itself is owned by the compaction module, which
    // reads and writes it. Pure `CREATE TABLE/INDEX IF NOT EXISTS`, so this is
    // idempotent on both a fresh and an already-upgraded database.
    conn.execute_batch(crate::compaction::CHECKPOINT_TABLE_MIGRATION)?;
    Ok(())
}

/// Installs a checkpoint and deletes the pruned prefix, all on the supplied
/// connection — pass an open transaction so the checkpoint insert and every
/// delete commit together and a crash can never leave history half-pruned with
/// no checkpoint to answer ancestry against.
///
/// Each pruned hash is removed from `changes`, from `change_parents` as both a
/// child and a parent (so the retained cut changes become clean roots and an
/// ancestry walk terminates at the boundary with no dangling edge into deleted
/// history), and from `group_heads`. The checkpoint frontier changes are *not*
/// in `pruned`, so they and the live history above them are retained intact.
pub fn commit_prune(
    conn: &Connection,
    checkpoint: &crate::compaction::Checkpoint,
    pruned: &[ChangeHash],
) -> Result<(), SyncError> {
    let group_id = checkpoint.group_id.as_str();
    // Per-group monotonic sequence so `latest_checkpoint` can pick the newest.
    let next_seq: i64 = conn.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM change_checkpoints WHERE group_id = ?1",
        [group_id],
        |r| r.get(0),
    )?;
    let checkpoint_hash = checkpoint.checkpoint_hash();
    conn.execute(
        "INSERT OR REPLACE INTO change_checkpoints \
         (checkpoint_hash, group_id, snapshot_hash, encoded, seq) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            &checkpoint_hash.as_bytes()[..],
            group_id,
            &checkpoint.snapshot_hash[..],
            checkpoint.canonical_encoding(),
            next_seq,
        ],
    )?;
    for hash in pruned {
        conn.execute(
            "DELETE FROM change_file_versions WHERE group_id = ?1 AND change_hash = ?2",
            rusqlite::params![group_id, &hash.0[..]],
        )?;
        conn.execute("DELETE FROM changes WHERE change_hash = ?1", [&hash.0[..]])?;
        conn.execute(
            "DELETE FROM change_parents WHERE child_hash = ?1 OR parent_hash = ?1",
            [&hash.0[..]],
        )?;
        conn.execute(
            "DELETE FROM group_heads WHERE group_id = ?1 AND change_hash = ?2",
            rusqlite::params![group_id, &hash.0[..]],
        )?;
    }
    // Pruning history can orphan file-version rows: a version referenced only
    // by a now-deleted change can never be materialized again, so it is dead
    // weight. Sweep the group's versions against what its retained changes
    // still reference, in the same transaction as the prune so a crash can
    // never leave a version deleted while a change that needs it survives.
    serving_authorization_index::sweep_unreferenced_file_versions(conn, group_id)?;
    Ok(())
}

/// Admits a verified peer change: if its ancestry is complete it is applied
/// (and any orphans it unblocks are promoted); otherwise it is buffered. The
/// caller MUST have already run `change::verify_change` — this function
/// assumes the change is authentic and authorized.
pub fn admit_change(
    conn: &Connection,
    change: &Change,
    applied: bool,
) -> Result<AdmitResult, SyncError> {
    serving_authorization_index::validate_referenced_versions(conn, change)?;
    if retained_history_integrity::validate_present_parent_shape(conn, change)? {
        retained_history_integrity::append_change(conn, change, applied)?;
        // The current change lands first, then any orphans its arrival
        // unblocked. All of them became durable in this call, so the caller
        // must project and gate every one — return the full set in append
        // order (current change first).
        let mut newly_admitted = vec![change.compute_hash()];
        newly_admitted.extend(orphan_integrity::promote_orphans(conn)?);
        Ok(AdmitResult { outcome: AdmitOutcome::Applied, newly_admitted })
    } else {
        // Record the edges now so `promote_orphans` can test completeness
        // cheaply once the parents land.
        let hash = change.compute_hash();
        for parent in &change.parents {
            conn.execute(
                "INSERT OR IGNORE INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
                rusqlite::params![&hash.0[..], &parent.0[..]],
            )?;
        }
        orphan_integrity::insert_orphan(conn, change, applied)?;
        Ok(AdmitResult { outcome: AdmitOutcome::Orphaned, newly_admitted: Vec::new() })
    }
}

/// Builds, signs, and appends a change for a local mutation. Its parents are
/// the group's current heads, so it narrows the head set to itself. Runs
/// entirely on the supplied connection, so passing an open transaction makes
/// the change append atomic with whatever index mutation shares it.
///
/// `auth` is the emitting device's authorization stamp (membership sequence,
/// epoch, and pinned policy-log head); it is baked into the signed change so
/// admission on any replica is judged against the membership/policy state the
/// author held, not against whatever the log says now.
pub fn emit_local_change(
    conn: &Connection,
    group_id: &str,
    ops: Vec<Op>,
    auth: ChangeAuth,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncError> {
    let parents = frontier_index::group_heads(conn, group_id)?;
    if parents.is_empty() {
        // An empty frontier is only legitimate for a group with no retained
        // history at all. `group_heads` is a derived index of `changes`; if
        // it lost its rows for a group that still has retained history (a
        // corrupted/missing index, not a fresh group), signing a change with
        // no parents here would silently start a second, disconnected root
        // under the same group_id.
        let has_history: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM changes WHERE group_id = ?1)",
            [group_id],
            |r| r.get(0),
        )?;
        if has_history {
            return Err(SyncError::CorruptState(format!(
                "cannot emit local change for group {group_id}: retained history exists but no \
                 head is recorded; refusing to start a competing root"
            )));
        }
    }
    let max_parent_lamport = frontier_index::max_parent_lamport(conn, &parents)?;
    let change = Change::create_signed(
        parents,
        max_parent_lamport,
        auth,
        DeviceId(emitter.device_id.clone()),
        FolderGroupId(group_id.to_string()),
        ops,
        &emitter.signing_key,
    );
    // `group_heads` is trusted by callers as this group's frontier, but it is
    // itself just a derived index; re-validate against `changes` before
    // signing so a foreign-group head injected (or corrupted) into it cannot
    // make this device sign a change that claims ancestry from a different
    // group's history, or one whose "parent" isn't actually retained at all.
    if !retained_history_integrity::validate_present_parent_shape(conn, &change)? {
        return Err(SyncError::CorruptState(format!(
            "cannot emit local change for group {group_id}: a recorded head is not actually \
             present in retained history"
        )));
    }
    retained_history_integrity::append_change(conn, &change, true)?;
    Ok(change)
}

/// Builds, signs, and appends a new local change onto caller-specified
/// `parents` rather than the group's current heads. Used by re-bootstrap to
/// squash an offline-diverged local branch (one whose head does not descend
/// from an incoming checkpoint frontier) into a single new change re-parented
/// onto the just-installed frontier -- at that point in the atomic installer
/// `group_heads` does not yet reflect the new frontier, so `emit_local_change`'s
/// own current-heads resolution cannot be reused as-is. The signed content is
/// otherwise identical: same signature/authorization shape, same structural
/// re-validation before appending.
pub fn emit_local_change_onto(
    conn: &Connection,
    group_id: &str,
    parents: Vec<ChangeHash>,
    ops: Vec<Op>,
    auth: ChangeAuth,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncError> {
    let max_parent_lamport = frontier_index::max_parent_lamport(conn, &parents)?;
    let change = Change::create_signed(
        parents,
        max_parent_lamport,
        auth,
        DeviceId(emitter.device_id.clone()),
        FolderGroupId(group_id.to_string()),
        ops,
        &emitter.signing_key,
    );
    if !retained_history_integrity::validate_present_parent_shape(conn, &change)? {
        return Err(SyncError::CorruptState(format!(
            "cannot emit local change for group {group_id}: a recorded parent is not actually \
             present in retained history"
        )));
    }
    retained_history_integrity::append_change(conn, &change, false)?;
    Ok(change)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change::{BlockHash, FileMeta, SyncPath, VersionBlock};
    use crate::types::RecordKind;
    use ed25519_dalek::SigningKey;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_dag_schema(&c).unwrap();
        c
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn test_version() -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    fn seed_test_version(conn: &Connection, group_id: &str) {
        put_file_version(conn, group_id, &test_version()).unwrap();
    }

    fn collapse_file_versions_to_v2(conn: &Connection, retained_group: &str) {
        conn.execute_batch(
            "ALTER TABLE file_versions RENAME TO file_versions_v3; \
             CREATE TABLE file_versions ( \
                 version_hash BLOB PRIMARY KEY, \
                 group_id TEXT NOT NULL, \
                 encoded BLOB NOT NULL);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO file_versions (version_hash, group_id, encoded) \
             SELECT version_hash, group_id, encoded FROM file_versions_v3 WHERE group_id = ?1",
            [retained_group],
        )
        .unwrap();
        conn.execute_batch("DROP TABLE file_versions_v3; DELETE FROM change_file_versions;")
            .unwrap();
    }

    #[test]
    fn v2_migration_reconstructs_cross_group_version_ownership_from_changes() {
        let c = conn();
        let version = test_version();
        put_file_version(&c, "group-a", &version).unwrap();
        emit_local_change(
            &c,
            "group-a",
            vec![Op::Create { path: SyncPath("a".into()), version: version.version_hash }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        put_file_version(&c, "group-b", &version).unwrap();
        emit_local_change(
            &c,
            "group-b",
            vec![Op::Create { path: SyncPath("b".into()), version: version.version_hash }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        collapse_file_versions_to_v2(&c, "group-a");

        init_dag_schema(&c).unwrap();

        assert!(get_file_version(&c, "group-a", &version.version_hash).unwrap().is_some());
        assert!(get_file_version(&c, "group-b", &version.version_hash).unwrap().is_some());
        let relations: i64 =
            c.query_row("SELECT COUNT(*) FROM change_file_versions", [], |row| row.get(0)).unwrap();
        assert_eq!(relations, 2);
    }

    #[test]
    fn v2_migration_rolls_back_when_a_retained_change_has_no_global_version() {
        let c = conn();
        let version = test_version();
        put_file_version(&c, "group-a", &version).unwrap();
        emit_local_change(
            &c,
            "group-a",
            vec![Op::Create { path: SyncPath("a".into()), version: version.version_hash }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        collapse_file_versions_to_v2(&c, "missing-group");

        let error = init_dag_schema(&c).expect_err("missing v2 metadata must fail closed");
        assert!(matches!(error, SyncError::CorruptState(_)));
        let columns: Vec<String> = c
            .prepare("PRAGMA table_info(file_versions)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(columns, vec!["version_hash", "group_id", "encoded"]);
        assert!(!c
            .prepare("PRAGMA table_info(file_versions)")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(5))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .contains(&2));
    }

    #[test]
    fn already_group_scoped_database_missing_cross_group_ownership_is_repaired() {
        // Reproduces a database that already carries the group-scoped
        // `file_versions` shape from an earlier, incomplete conversion (the
        // historical bug in `3edca8f0`, which copied each v2 row under only
        // its first-writer group): the `if legacy_file_versions...` branch
        // above never fires for it, since the shape is already current, so
        // only the unconditional `repair_missing_file_version_ownership`
        // pass can close this gap.
        let c = conn();
        let version = test_version();
        put_file_version(&c, "group-a", &version).unwrap();
        emit_local_change(
            &c,
            "group-a",
            vec![Op::Create { path: SyncPath("a".into()), version: version.version_hash }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        put_file_version(&c, "group-b", &version).unwrap();
        emit_local_change(
            &c,
            "group-b",
            vec![Op::Create { path: SyncPath("b".into()), version: version.version_hash }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        // Simulate the prior migration's bug directly: drop group-b's row
        // while leaving the table itself in the (already current)
        // group-scoped shape.
        c.execute(
            "DELETE FROM file_versions WHERE group_id = 'group-b' AND version_hash = ?1",
            [&version.version_hash.0[..]],
        )
        .unwrap();
        assert!(get_file_version(&c, "group-b", &version.version_hash).unwrap().is_none());

        init_dag_schema(&c).unwrap();

        assert!(get_file_version(&c, "group-a", &version.version_hash).unwrap().is_some());
        assert!(
            get_file_version(&c, "group-b", &version.version_hash).unwrap().is_some(),
            "a database already in the group-scoped shape must still have \
             cross-group ownership repaired from retained Changes"
        );
    }

    #[test]
    fn schema_init_repairs_file_version_ownership_referenced_only_by_a_buffered_orphan() {
        // The plain `changes`-table backfill cannot see a version referenced
        // only by a change still buffered in `orphan_changes` (arrived
        // before its parent). Left unrepaired, that group's later
        // `promote_orphans` would fail `validate_referenced_versions`
        // forever once the parent does arrive.
        let sender = conn();
        let version = test_version();
        put_file_version(&sender, "group-b", &version).unwrap();
        let orphan = emit_local_change(
            &sender,
            "group-b",
            vec![Op::Create { path: SyncPath("b".into()), version: version.version_hash }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();

        let c = conn();
        put_file_version(&c, "group-a", &version).unwrap();
        insert_orphan(&c, &orphan, false).unwrap();
        assert!(get_file_version(&c, "group-b", &version.version_hash).unwrap().is_none());

        init_dag_schema(&c).unwrap();

        assert!(
            get_file_version(&c, "group-b", &version.version_hash).unwrap().is_some(),
            "a version referenced only by a buffered orphan must still be \
             repaired into that orphan's group"
        );
        // An orphan is not yet admitted, so repairing its group's version
        // ownership must not also grant it block-serving authorization.
        let relations: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM change_file_versions WHERE group_id = 'group-b'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(relations, 0);
    }

    #[test]
    fn list_unapplied_fails_closed_on_corrupt_retained_change() {
        let c = conn();
        c.execute(
            "INSERT INTO changes \
             (change_hash, group_id, device_id, lamport, encoded, applied) \
             VALUES (?1, 'g', 'device-a', 1, ?2, 0)",
            rusqlite::params![vec![0x72u8; 32], b"not-a-change".as_slice()],
        )
        .unwrap();

        let error = list_unapplied(&c, "g").expect_err("corrupt retry state must be visible");
        assert!(matches!(error, SyncError::CorruptState(_)));
    }

    #[test]
    fn block_reference_authorization_is_group_scoped() {
        let c = conn();
        let block_hash = vec![0xabu8; 32];
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        put_file_version(&c, "group-a", &version).unwrap();

        assert!(
            !group_file_version_references_block(&c, "group-a", &block_hash).unwrap(),
            "an unreferenced version must not authorize block service"
        );
        emit_local_change(
            &c,
            "group-a",
            vec![Op::Create { path: SyncPath("a.bin".into()), version: version.version_hash }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        assert!(group_file_version_references_block(&c, "group-a", &block_hash).unwrap());
        assert!(!group_file_version_references_block(&c, "group-b", &block_hash).unwrap());
        assert!(!group_file_version_references_block(&c, "group-a", &[0xcdu8; 32]).unwrap());
    }

    #[test]
    fn admitted_metadata_does_not_forge_block_provenance() {
        let c = conn();
        let block_hash = vec![0xabu8; 32];
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        put_file_version(&c, "group-a", &version).unwrap();
        emit_local_change(
            &c,
            "group-a",
            vec![Op::Create {
                path: SyncPath("attacker-controlled.bin".into()),
                version: version.version_hash,
            }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();

        assert!(group_file_version_references_block(&c, "group-a", &block_hash).unwrap());
        assert!(
            !group_has_block_provenance(&c, "group-a", &block_hash).unwrap(),
            "even admitted, correctly signed metadata must not prove byte ownership"
        );

        record_group_block_provenance(&c, "group-b", std::slice::from_ref(&block_hash)).unwrap();
        assert!(group_has_block_provenance(&c, "group-b", &block_hash).unwrap());
        assert!(
            !group_has_block_provenance(&c, "group-a", &block_hash).unwrap(),
            "physical dedup must not leak provenance across groups"
        );

        record_group_block_provenance(&c, "group-a", std::slice::from_ref(&block_hash)).unwrap();
        assert!(group_has_block_provenance(&c, "group-a", &block_hash).unwrap());
    }

    #[test]
    fn rejected_change_rolls_back_its_versions_and_grants_no_block_capability() {
        let state = crate::index::SyncState::open_in_memory().unwrap();
        let block_hash = vec![0x42; 32];
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        let signing = key();
        let mut change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-A".into()),
            FolderGroupId("group-a".into()),
            vec![Op::Create { path: SyncPath("poison.bin".into()), version: version.version_hash }],
            &signing,
        );
        change.lamport = 99;
        change.sign(&signing);

        assert!(state.dag_admit_change_with_versions(&change, &[version.clone()], false).is_err());
        assert!(!state.dag_has_file_version("group-a", &version.version_hash).unwrap());
        assert!(!state.dag_group_file_version_references_block("group-a", &block_hash).unwrap());
    }

    #[test]
    fn orphan_version_grants_no_block_capability_until_promotion() {
        let c = conn();
        let block_hash = vec![0x24; 32];
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        put_file_version(&c, "g", &version).unwrap();
        let signing = key();
        let parent = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-A".into()),
            FolderGroupId("g".into()),
            vec![Op::Delete { path: SyncPath("old.bin".into()) }],
            &signing,
        );
        let child = Change::create_signed(
            vec![parent.compute_hash()],
            parent.lamport,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-A".into()),
            FolderGroupId("g".into()),
            vec![Op::Create { path: SyncPath("new.bin".into()), version: version.version_hash }],
            &signing,
        );

        assert_eq!(admit_change(&c, &child, false).unwrap().outcome, AdmitOutcome::Orphaned);
        assert!(!group_file_version_references_block(&c, "g", &block_hash).unwrap());
        assert_eq!(admit_change(&c, &parent, false).unwrap().outcome, AdmitOutcome::Applied);
        assert!(group_file_version_references_block(&c, "g", &block_hash).unwrap());
    }

    #[test]
    fn schema_init_backfills_admitted_change_version_relations() {
        let c = conn();
        let block_hash = vec![0x66; 32];
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        put_file_version(&c, "g", &version).unwrap();
        emit_local_change(
            &c,
            "g",
            vec![Op::Create { path: SyncPath("a".into()), version: version.version_hash }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        c.execute("DELETE FROM change_file_versions", []).unwrap();
        assert!(!group_file_version_references_block(&c, "g", &block_hash).unwrap());

        init_dag_schema(&c).unwrap();
        assert!(group_file_version_references_block(&c, "g", &block_hash).unwrap());
    }

    #[test]
    fn version_sweep_fails_closed_on_a_corrupt_retained_change() {
        let c = conn();
        let version = test_version();
        put_file_version(&c, "g", &version).unwrap();
        c.execute(
            "INSERT INTO changes \
             (change_hash, group_id, device_id, lamport, encoded, applied) \
             VALUES (?1, 'g', 'device-A', 1, ?2, 1)",
            rusqlite::params![vec![0x91u8; 32], b"not-a-change".as_slice()],
        )
        .unwrap();

        let error = sweep_unreferenced_file_versions(&c, "g")
            .expect_err("corrupt retained history must abort version GC");
        assert!(matches!(error, SyncError::CorruptState(_)));
        assert!(get_file_version(&c, "g", &version.version_hash).unwrap().is_some());
    }

    fn create_op(path: &str) -> Op {
        Op::Create { path: SyncPath(path.into()), version: test_version().version_hash }
    }

    fn emitter() -> ChangeEmitter {
        ChangeEmitter::new("device-A", key())
    }

    #[test]
    fn local_emission_chains_heads() {
        let c = conn();
        let em = emitter();

        let c1 =
            emit_local_change(&c, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em).unwrap();
        assert_eq!(c1.parents, vec![]);
        assert_eq!(c1.lamport, 1);
        assert_eq!(group_heads(&c, "g").unwrap(), vec![c1.compute_hash()]);

        let c2 =
            emit_local_change(&c, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em).unwrap();
        // c2 descends from c1, so c1 is no longer a head.
        assert_eq!(c2.parents, vec![c1.compute_hash()]);
        assert_eq!(c2.lamport, 2);
        assert_eq!(group_heads(&c, "g").unwrap(), vec![c2.compute_hash()]);

        assert!(is_ancestor(&c, &c1.compute_hash(), &c2.compute_hash()).unwrap());
        assert!(!is_ancestor(&c, &c2.compute_hash(), &c1.compute_hash()).unwrap());
    }

    #[test]
    fn append_is_idempotent_under_duplicate_delivery() {
        let c = conn();
        let change =
            emit_local_change(&c, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &emitter())
                .unwrap();
        // Re-appending the identical change changes nothing.
        assert!(!append_change(&c, &change, true).unwrap());
        let count: i64 = c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1);
        assert_eq!(group_heads(&c, "g").unwrap().len(), 1);
    }

    #[test]
    fn concurrent_changes_are_both_heads() {
        // Two devices edit from the same (empty) frontier without seeing
        // each other: both become heads.
        let c = conn();
        let a = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[1u8; 32]));
        let b = ChangeEmitter::new("device-B", SigningKey::from_bytes(&[2u8; 32]));
        let ca =
            emit_local_change(&c, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &a).unwrap();
        seed_test_version(&c, "g");
        // Force B's change to also root at the empty frontier by admitting it
        // as if it arrived from a peer (its parents = []).
        let cb = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-B".into()),
            FolderGroupId("g".into()),
            vec![create_op("b")],
            &SigningKey::from_bytes(&[2u8; 32]),
        );
        let _ = b;
        assert_eq!(admit_change(&c, &cb, true).unwrap().outcome, AdmitOutcome::Applied);
        let mut heads = group_heads(&c, "g").unwrap();
        heads.sort();
        let mut expected = vec![ca.compute_hash(), cb.compute_hash()];
        expected.sort();
        assert_eq!(heads, expected);
    }

    #[test]
    fn out_of_order_arrival_is_orphaned_then_promoted() {
        // Build a chain root -> child on a "sender", then deliver child
        // first to a fresh receiver.
        let sender = conn();
        let em = emitter();
        let root =
            emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let child =
            emit_local_change(&sender, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        // Child arrives before its parent: held, not applied.
        assert_eq!(admit_change(&recv, &child, true).unwrap().outcome, AdmitOutcome::Orphaned);
        assert!(!has_change(&recv, &child.compute_hash()).unwrap());
        assert!(group_heads(&recv, "g").unwrap().is_empty());

        // Parent arrives: it applies and promotes the buffered child.
        assert_eq!(admit_change(&recv, &root, true).unwrap().outcome, AdmitOutcome::Applied);
        assert!(has_change(&recv, &root.compute_hash()).unwrap());
        assert!(has_change(&recv, &child.compute_hash()).unwrap());
        // The frontier converged to the single child head, just like the sender.
        assert_eq!(group_heads(&recv, "g").unwrap(), vec![child.compute_hash()]);
        assert_eq!(group_heads(&recv, "g").unwrap(), group_heads(&sender, "g").unwrap());
    }

    #[test]
    fn promote_orphans_returns_promoted_hashes_in_append_order() {
        // A chain root -> c1 -> c2 built on a sender, with the two descendants
        // delivered to a fresh receiver before their common ancestor. When the
        // ancestor lands, promotion must return the promoted changes' hashes in
        // the order they were appended (oldest-first): the admission caller
        // projects each promoted orphan's paths, so it needs their identities,
        // not just a count.
        let sender = conn();
        let em = emitter();
        let root =
            emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let c1 =
            emit_local_change(&sender, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let c2 =
            emit_local_change(&sender, "g", vec![create_op("c")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        // Both descendants arrive before the root: buffered, nothing promoted.
        assert_eq!(admit_change(&recv, &c1, true).unwrap().outcome, AdmitOutcome::Orphaned);
        assert_eq!(admit_change(&recv, &c2, true).unwrap().outcome, AdmitOutcome::Orphaned);

        // Land the root directly and promote: c1 unblocks first (its parent is
        // the root), then c2 (its parent is c1).
        assert!(append_change(&recv, &root, true).unwrap());
        let promoted = promote_orphans(&recv).unwrap();
        assert_eq!(promoted, vec![c1.compute_hash(), c2.compute_hash()]);
    }

    #[test]
    fn admit_change_reports_the_current_change_and_promoted_orphans() {
        // The other half of the same guarantee, but through `admit_change`:
        // admitting the root that unblocks a buffered child must report BOTH
        // the root and the promoted child in `newly_admitted`, root first.
        let sender = conn();
        let em = emitter();
        let root =
            emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let child =
            emit_local_change(&sender, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        let orphaned = admit_change(&recv, &child, true).unwrap();
        assert_eq!(orphaned.outcome, AdmitOutcome::Orphaned);
        assert!(orphaned.newly_admitted.is_empty(), "an orphaned change admits nothing yet");

        let applied = admit_change(&recv, &root, true).unwrap();
        assert_eq!(applied.outcome, AdmitOutcome::Applied);
        assert_eq!(applied.newly_admitted, vec![root.compute_hash(), child.compute_hash()]);
    }

    #[test]
    fn delivery_order_does_not_change_final_heads() {
        // Same three-change set delivered in two different orders converges
        // to the same head set (commutativity at the store level).
        let sender = conn();
        let em = emitter();
        let r = emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
            .unwrap();
        let m = emit_local_change(&sender, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em)
            .unwrap();
        let t = emit_local_change(&sender, "g", vec![create_op("c")], ChangeAuth::PLACEHOLDER, &em)
            .unwrap();

        let forward = conn();
        seed_test_version(&forward, "g");
        for ch in [&r, &m, &t] {
            admit_change(&forward, ch, true).unwrap();
        }
        let reverse = conn();
        seed_test_version(&reverse, "g");
        for ch in [&t, &r, &m] {
            admit_change(&reverse, ch, true).unwrap();
        }
        assert_eq!(group_heads(&forward, "g").unwrap(), group_heads(&reverse, "g").unwrap());
        assert_eq!(group_heads(&forward, "g").unwrap(), vec![t.compute_hash()]);
    }

    #[test]
    fn admission_rejects_malformed_lamport() {
        let c = conn();
        let em = emitter();
        let root =
            emit_local_change(&c, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em).unwrap();
        seed_test_version(&c, "g");
        let bad = Change::create_signed(
            vec![root.compute_hash()],
            99,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-B".into()),
            FolderGroupId("g".into()),
            vec![create_op("b")],
            &SigningKey::from_bytes(&[2u8; 32]),
        );
        assert!(admit_change(&c, &bad, true).is_err());
    }

    #[test]
    fn admission_rejects_file_version_from_another_group() {
        let c = conn();
        put_file_version(&c, "other-group", &test_version()).unwrap();
        let bad = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-B".into()),
            FolderGroupId("g".into()),
            vec![create_op("b")],
            &SigningKey::from_bytes(&[2u8; 32]),
        );
        assert!(admit_change(&c, &bad, true).is_err());
    }

    #[test]
    fn identical_file_version_is_independently_owned_by_each_group() {
        let c = conn();
        let version = test_version();
        assert!(put_file_version(&c, "group-a", &version).unwrap());
        assert!(put_file_version(&c, "group-b", &version).unwrap());
        assert!(has_file_version(&c, "group-a", &version.version_hash).unwrap());
        assert!(has_file_version(&c, "group-b", &version.version_hash).unwrap());
        assert_eq!(
            get_file_version(&c, "group-b", &version.version_hash).unwrap().unwrap(),
            version
        );
    }

    #[test]
    fn device_frontier_replaces_and_removes() {
        let c = conn();
        let h1 = ChangeHash([1u8; 32]);
        let h2 = ChangeHash([2u8; 32]);
        let h3 = ChangeHash([3u8; 32]);

        // A frontier can carry several concurrent heads.
        set_device_frontier(&c, "g", "dev", &[h2, h1]).unwrap();
        assert_eq!(get_device_frontier(&c, "g", "dev").unwrap(), vec![h1, h2]);

        // Setting replaces the whole frontier rather than accumulating.
        set_device_frontier(&c, "g", "dev", &[h3]).unwrap();
        assert_eq!(get_device_frontier(&c, "g", "dev").unwrap(), vec![h3]);

        // Removal clears it entirely.
        remove_device_frontier(&c, "g", "dev").unwrap();
        assert!(get_device_frontier(&c, "g", "dev").unwrap().is_empty());
    }

    #[test]
    fn encoded_bytes_are_served_verbatim() {
        let c = conn();
        let change =
            emit_local_change(&c, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &emitter())
                .unwrap();
        let served = get_encoded(&c, &change.compute_hash()).unwrap().unwrap();
        assert_eq!(served, change.to_wire_bytes());
        // A relayed change round-trips to the identical change.
        assert_eq!(Change::from_wire_bytes(&served).unwrap(), change);
    }

    /// The dual-write path: `upsert_file_emitting_change` must land the index
    /// row and the signed change in one commit, with the change becoming the
    /// group's sole head.
    #[test]
    fn dual_write_commits_index_row_and_change_together() {
        use crate::index::SyncState;
        use crate::types::FileRecord;
        use crate::version_vector::VersionVector;

        let state = SyncState::open_in_memory().unwrap();
        state.set_local_change_auth_provider(std::sync::Arc::new(|_| {
            Ok(ChangeAuth { auth_seq: 7, auth_epoch: 3, policy_head_hash: [9u8; 32] })
        }));
        let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[7u8; 32]));
        let mut version = VersionVector::new();
        version.increment("device-A");
        let record = FileRecord {
            path: "a.txt".into(),
            size: 3,
            mtime_unix_nanos: 1,
            version,
            blocks: vec![],
            deleted: false,
        };
        let hash = state
            .upsert_file_emitting_change(
                "g",
                &record,
                "device-A",
                vec![create_op("a.txt")],
                &[],
                None,
                &em,
            )
            .unwrap();

        assert!(state.get_file("g", "a.txt").unwrap().is_some());
        assert!(state.dag_has_change(&hash).unwrap());
        assert_eq!(state.dag_group_heads("g").unwrap(), vec![hash]);
        let decoded = state.dag_get_change(&hash).unwrap().unwrap();
        assert_eq!(decoded.compute_hash(), hash);
        assert_eq!(decoded.auth_seq, 7);
        assert_eq!(decoded.auth_epoch, 3);
        assert_eq!(decoded.policy_head_hash, [9u8; 32]);

        // A subsequent tombstone chains from the first change and becomes the
        // new sole head.
        let del = state.mark_deleted_emitting_change("g", "a.txt", "device-A", 2, &em).unwrap();
        assert_eq!(state.dag_group_heads("g").unwrap(), vec![del]);
        assert!(state.dag_is_ancestor(&hash, &del).unwrap());
        assert!(state.get_file("g", "a.txt").unwrap().unwrap().deleted);
    }
}
