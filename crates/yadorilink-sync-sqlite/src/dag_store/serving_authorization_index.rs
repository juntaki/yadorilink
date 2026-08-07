//! The block-service authorization boundary: `file_versions` (content-
//! addressed version bytes, scoped per group), `change_file_versions` (which
//! admitted change justifies a group holding a given version -- this is what
//! [`group_file_version_references_block`] actually consults to decide
//! whether to serve a physical block), and `group_block_provenance` (which
//! groups this device actually obtained verified block bytes through). Treat
//! `change_file_versions` as a security boundary, not a cache: an extra,
//! unjustified relation here can manufacture block-serving rights that the
//! group's signed history never granted, which is exactly what
//! [`prune_unjustified_change_file_versions`] guards against.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::change::{Change, Op};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_root_authority::reserved_namespace::{
    path_has_artefact_component_in_wire_path, path_has_non_portable_wire_component,
};
use yadorilink_root_authority::sync_root_lock::wire_path_names_sync_root_lock;

/// Whether a content-addressed file version is present.
pub fn has_file_version(
    conn: &Connection,
    group_id: &str,
    hash: &VersionHash,
) -> Result<bool, SyncSqliteError> {
    let present: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM file_versions WHERE group_id = ?1 AND version_hash = ?2",
            rusqlite::params![group_id, &hash.0[..]],
            |r| r.get(0),
        )
        .optional()?;
    Ok(present.is_some())
}

pub(crate) fn op_version_hash(op: &Op) -> Option<&VersionHash> {
    match op {
        Op::Put { version, .. } | Op::Move { version, .. } => Some(version),
        Op::Delete { .. } => None,
    }
}

/// Rejects a change that names a versioned reserved-namespace artefact (see
/// `yadorilink_root_authority::reserved_namespace`) or this device's own sync-root lock file
/// (see `yadorilink_root_authority::sync_root_lock`) anywhere it can appear in an op: a
/// `Put`/`Delete` path, or either side of a `Move`. Applied before any
/// other admission check, matching the reserved namespace's requirement
/// that a peer cannot name one of its own artefact paths into another
/// device's index by shipping a change that claims it — a user cannot
/// un-ignore this any more than they could locally, and a peer cannot
/// route around it either.
///
/// The sync-root lock check closes a real hole this predicate alone did not:
/// without it, a change naming `.yadorilink-root.lock` was admitted and
/// later materialized, replacing the on-disk lock file out from under this
/// device's live `flock` — on Unix the held lock stays bound to the
/// now-unlinked inode while a *second* daemon happily locks the fresh file
/// materialization just created at the same path, so both processes end up
/// believing they exclusively own this sync root, which is precisely the
/// state `yadorilink_root_authority::sync_root_lock` exists to make unreachable.
///
/// Deliberately keys on [`path_has_artefact_component_in_wire_path`] /
/// [`yadorilink_root_authority::sync_root_lock::wire_path_names_sync_root_lock`], NOT either
/// function's host-`Path` form: `op`'s paths were authored by a remote peer,
/// not walked off this device's own disk, so finding component boundaries
/// via this process's own `std::path::Path` would make rejection depend on
/// which OS happens to be running admission — see
/// [`path_has_artefact_component_in_wire_path`]'s doc comment for the
/// platform-split this would otherwise cause. Also, NOT the broader
/// exclusion predicate `path_has_reserved_component`(`_in_wire_path`): the
/// legacy `.yadorilink-tmp.` marker must never fail admission. It is a
/// substring match within a component (real user content can precede it),
/// so rejecting it here could permanently block a legitimate file; and
/// history predating this module can already contain a legacy-marked path
/// that was admitted before anything excluded it — rejecting that on
/// replay would turn an upgraded peer into a permanent sync stall for the
/// whole group. See `reserved_namespace`'s "Two predicates, not one". The
/// sync-root lock file has no such look-alike concern (it is an exact,
/// unambiguous name this device itself owns), so it is rejected outright
/// rather than merely excluded.
pub(crate) fn validate_no_reserved_paths(change: &Change) -> Result<(), SyncSqliteError> {
    for op in &change.ops {
        let paths: Vec<&str> = match op {
            Op::Put { path, .. } | Op::Delete { path } => vec![path.as_str()],
            Op::Move { from, to, .. } => vec![from.as_str(), to.as_str()],
        };
        for path in paths {
            if path_has_artefact_component_in_wire_path(path)
                || wire_path_names_sync_root_lock(path)
            {
                return Err(SyncSqliteError::ReservedNamespaceCollision(path.to_string()));
            }
            // A path that would not survive a Windows peer's own trailing
            // dot/space normalization is refused here too, and for the same
            // host-independence reason as the check above: two distinct
            // paths differing only in a trailing '.'/' ' otherwise both get
            // admitted as independent index rows and silently collide onto
            // one on-disk name the moment either materializes on a Windows
            // device. See `path_has_non_portable_wire_component`'s doc
            // comment for the full mechanism.
            if path_has_non_portable_wire_component(path) {
                return Err(SyncSqliteError::NonPortablePath(path.to_string()));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_referenced_versions(
    conn: &Connection,
    change: &Change,
) -> Result<(), SyncSqliteError> {
    for op in &change.ops {
        let Some(version_hash) = op_version_hash(op) else { continue };
        if !has_file_version(conn, change.group_id.as_str(), version_hash)? {
            return Err(SyncSqliteError::NotFound(format!(
                "change references missing file version {}",
                version_hash.to_hex()
            )));
        }
    }
    Ok(())
}

/// The file version stored under `hash`, decoded from its canonical bytes, or
/// `None`. The decoded version's hash is recomputed and checked against the
/// key, so a lookup only ever returns a version whose bytes actually hash to
/// the requested address — a corrupt row is a clean error, never silently
/// mismatched content.
pub fn get_file_version(
    conn: &Connection,
    group_id: &str,
    hash: &VersionHash,
) -> Result<Option<FileVersion>, SyncSqliteError> {
    let encoded: Option<Vec<u8>> = conn
        .query_row(
            "SELECT encoded FROM file_versions WHERE group_id = ?1 AND version_hash = ?2",
            rusqlite::params![group_id, &hash.0[..]],
            |r| r.get(0),
        )
        .optional()?;
    match encoded {
        Some(bytes) => {
            let version = FileVersion::from_canonical_encoding(&bytes)
                .map_err(|_| SyncSqliteError::NotFound("stored file version is corrupt".into()))?;
            if version.version_hash != *hash {
                return Err(SyncSqliteError::NotFound(
                    "stored file version hash does not match its key".into(),
                ));
            }
            Ok(Some(version))
        }
        None => Ok(None),
    }
}

/// Whether any retained file version in `group_id` references `block_hash`.
/// Conflict-copy materialization may request a block before the derived copy
/// path has been projected into the current-file index; the DAG version is the
/// durable group-scoped proof that serving that content is authorized.
pub fn group_file_version_references_block(
    conn: &Connection,
    group_id: &str,
    block_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    if versions_reference_block(
        conn,
        "SELECT DISTINCT fv.encoded \
         FROM change_file_versions cfv \
         JOIN changes c ON c.change_hash = cfv.change_hash AND c.group_id = cfv.group_id \
         JOIN file_versions fv ON fv.group_id = cfv.group_id \
                              AND fv.version_hash = cfv.version_hash \
         WHERE cfv.group_id = ?1",
        group_id,
        block_hash,
    )? {
        return Ok(true);
    }
    // A version whose only referencing change was compacted away falls
    // through to this second, ordinarily-empty source rather than costing
    // every ordinary (uncompacted) lookup a UNION/DISTINCT merge against it.
    versions_reference_block(
        conn,
        "SELECT DISTINCT fv.encoded \
         FROM compacted_file_version_authorization cfa \
         JOIN file_versions fv ON fv.group_id = cfa.group_id \
                              AND fv.version_hash = cfa.version_hash \
         WHERE cfa.group_id = ?1",
        group_id,
        block_hash,
    )
}

fn versions_reference_block(
    conn: &Connection,
    query: &str,
    group_id: &str,
    block_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    let mut stmt = conn.prepare(query)?;
    let mut rows = stmt.query([group_id])?;
    while let Some(row) = rows.next()? {
        let encoded: Vec<u8> = row.get(0)?;
        let version = FileVersion::from_canonical_encoding(&encoded)
            .map_err(|_| SyncSqliteError::NotFound("stored file version is corrupt".into()))?;
        if version.blocks.iter().any(|block| block.hash.0.as_slice() == block_hash) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Records that this device obtained verified block bytes through `group_id`.
/// Callers must only invoke this after a local chunk-store write or after a
/// fetched response has passed hash/size verification and been persisted.
pub fn record_group_block_provenance(
    conn: &Connection,
    group_id: &str,
    block_hashes: &[Vec<u8>],
) -> Result<(), SyncSqliteError> {
    let mut stmt = conn.prepare(
        "INSERT OR IGNORE INTO group_block_provenance (group_id, block_hash) VALUES (?1, ?2)",
    )?;
    for block_hash in block_hashes {
        stmt.execute(rusqlite::params![group_id, block_hash])?;
    }
    Ok(())
}

/// Records that `version_hash` is authorized for `group_id` independently of
/// any single admitted change — the re-bootstrap/compaction persistence layer
/// calls this for every version it re-derives from live materialized-file
/// index state, so a superseded-but-retained version does not lose its
/// block-serving justification merely because the change that originally
/// admitted it was pruned. Idempotent.
pub fn record_compacted_file_version_authorization(
    conn: &Connection,
    group_id: &str,
    version_hash: &VersionHash,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT OR IGNORE INTO compacted_file_version_authorization (group_id, version_hash) \
         VALUES (?1, ?2)",
        rusqlite::params![group_id, &version_hash.0[..]],
    )?;
    Ok(())
}

/// Whether verified bytes for `block_hash` were actually obtained through
/// `group_id`, independently of any peer-supplied metadata references.
pub fn group_has_block_provenance(
    conn: &Connection,
    group_id: &str,
    block_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM group_block_provenance WHERE group_id = ?1 AND block_hash = ?2)",
        rusqlite::params![group_id, block_hash],
        |row| row.get(0),
    )?)
}

/// Persists a file version, keyed by its content hash. Idempotent — re-putting
/// an identical version is a no-op and returns `false`. The version's hash is
/// re-derived from its bytes and must match its `version_hash` field before
/// anything is written, so a version can never be stored under a hash that does
/// not describe its content (whether it came from local emission or a peer's
/// wire encoding). Runs on the supplied connection, so passing an open
/// transaction stores the version atomically with the change that references
/// it.
pub fn put_file_version(
    conn: &Connection,
    group_id: &str,
    version: &FileVersion,
) -> Result<bool, SyncSqliteError> {
    version.verify_hash().map_err(|_| {
        SyncSqliteError::NotFound("file version hash does not match its encoding".into())
    })?;
    let changed = conn.execute(
        "INSERT OR IGNORE INTO file_versions (version_hash, group_id, encoded) VALUES (?1, ?2, ?3)",
        rusqlite::params![&version.version_hash.0[..], group_id, version.canonical_encoding()],
    )?;
    Ok(changed > 0)
}

/// Deletes every `file_versions` row for `group_id` that no retained change
/// references *and* that is not explicitly authorized via
/// `compacted_file_version_authorization` (a version compaction/re-bootstrap
/// deliberately retains independently of any single admitted change — see
/// [`record_compacted_file_version_authorization`]). Recomputes the live
/// reference set by decoding the group's remaining changes' ops plus the
/// authorization table, so it is correct regardless of which changes the
/// prune/install removed. Bounded by the checkpoint frontier, so the full
/// scan is acceptable.
pub fn sweep_unreferenced_file_versions(
    conn: &Connection,
    group_id: &str,
) -> Result<(), SyncSqliteError> {
    // `commit_prune` calls this only after every Change/edge deletion. Close the
    // checkpoint-opened prune context before doing any fallible scan work, so a
    // later unrelated history deletion cannot inherit stale prune authority.
    // In the intended enclosing transaction, any subsequent error rolls this
    // clear and the preceding prune back together.
    super::retained_history_integrity::finish_prune_context(conn, group_id)?;

    use std::collections::HashSet;
    let mut referenced: HashSet<[u8; 32]> = HashSet::new();
    {
        let mut stmt = conn.prepare("SELECT encoded FROM changes WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let change = Change::from_wire_bytes(&row?).map_err(|error| {
                SyncSqliteError::CorruptState(format!(
                    "cannot compact group {group_id}: retained change is corrupt: {error}"
                ))
            })?;
            for op in &change.ops {
                match op {
                    Op::Put { version, .. } | Op::Move { version, .. } => {
                        referenced.insert(version.0);
                    }
                    Op::Delete { .. } => {}
                }
            }
        }
    }
    {
        let mut stmt = conn.prepare(
            "SELECT version_hash FROM compacted_file_version_authorization WHERE group_id = ?1",
        )?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let bytes = row?;
            if let Ok(array) = <[u8; 32]>::try_from(bytes.as_slice()) {
                referenced.insert(array);
            }
        }
    }
    let stored: Vec<Vec<u8>> = {
        let mut stmt =
            conn.prepare("SELECT version_hash FROM file_versions WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
        let mut v = Vec::new();
        for row in rows {
            v.push(row?);
        }
        v
    };
    for vh in stored {
        let retained = <[u8; 32]>::try_from(vh.as_slice())
            .map(|arr| referenced.contains(&arr))
            .unwrap_or(false);
        if !retained {
            conn.execute(
                "DELETE FROM file_versions WHERE group_id = ?1 AND version_hash = ?2",
                rusqlite::params![group_id, &vh[..]],
            )?;
        }
    }
    Ok(())
}

/// Records exactly the versions referenced by an admitted change. Mere
/// presence in `file_versions` is not a block-serving capability.
pub(crate) fn record_change_file_versions(
    conn: &Connection,
    change: &Change,
) -> Result<(), SyncSqliteError> {
    let hash = change.compute_hash();
    for op in &change.ops {
        let Some(version_hash) = op_version_hash(op) else { continue };
        conn.execute(
            "INSERT OR IGNORE INTO change_file_versions \
             (group_id, change_hash, version_hash) VALUES (?1, ?2, ?3)",
            rusqlite::params![change.group_id.as_str(), &hash.0[..], &version_hash.0[..]],
        )?;
    }
    Ok(())
}

fn file_version_encoding_matches(encoded: &[u8], expected: &VersionHash) -> bool {
    matches!(
        FileVersion::from_canonical_encoding(encoded),
        Ok(version) if version.version_hash == *expected
    )
}

fn find_valid_file_version_encoding(
    conn: &Connection,
    hash: &VersionHash,
) -> Result<Option<Vec<u8>>, SyncSqliteError> {
    let mut stmt = conn
        .prepare("SELECT encoded FROM file_versions WHERE version_hash = ?1 ORDER BY group_id")?;
    let rows = stmt.query_map([&hash.0[..]], |row| row.get::<_, Vec<u8>>(0))?;
    for row in rows {
        let encoded = row?;
        if file_version_encoding_matches(&encoded, hash) {
            return Ok(Some(encoded));
        }
    }
    Ok(None)
}

/// Repairs the versions one change references into `group_id`'s scope. Returns
/// `false` only for a buffered orphan whose referenced version has no valid
/// retained encoding in any group; admitted history returns `CorruptState`
/// instead. An admitted change also gets its `change_file_versions` binding
/// recorded; an orphan must not grant block-serving authorization before it is
/// promoted.
pub(crate) fn repair_change_file_versions(
    tx: &Connection,
    change: &Change,
    admitted: bool,
) -> Result<bool, SyncSqliteError> {
    let change_hash = change.compute_hash();
    let mut seen = std::collections::HashSet::new();
    let mut repairs: Vec<([u8; 32], Vec<u8>)> = Vec::new();

    for op in &change.ops {
        let Some(version_hash) = op_version_hash(op) else { continue };
        if !seen.insert(version_hash.0) {
            continue;
        }

        let target_encoded: Option<Vec<u8>> = tx
            .query_row(
                "SELECT encoded FROM file_versions WHERE group_id = ?1 AND version_hash = ?2",
                rusqlite::params![change.group_id.as_str(), &version_hash.0[..]],
                |row| row.get(0),
            )
            .optional()?;
        if target_encoded
            .as_deref()
            .is_some_and(|encoded| file_version_encoding_matches(encoded, version_hash))
        {
            continue;
        }

        let Some(encoded_version) = find_valid_file_version_encoding(tx, version_hash)? else {
            if admitted {
                return Err(SyncSqliteError::CorruptState(format!(
                    "cannot repair file version ownership: change {} in group {} references version {} with no valid retained bytes in any group",
                    hex::encode(change_hash.0),
                    change.group_id.as_str(),
                    hex::encode(version_hash.0),
                )));
            }
            return Ok(false);
        };
        repairs.push((version_hash.0, encoded_version));
    }

    for (version_hash, encoded_version) in repairs {
        tx.execute(
            "INSERT INTO file_versions (version_hash, group_id, encoded) VALUES (?1, ?2, ?3) \
             ON CONFLICT(group_id, version_hash) DO UPDATE SET encoded = excluded.encoded",
            rusqlite::params![&version_hash[..], change.group_id.as_str(), encoded_version],
        )?;
    }
    if admitted {
        record_change_file_versions(tx, change)?;
    }
    Ok(true)
}

/// Removes any `change_file_versions` row for an admitted change that its own
/// decoded `ops` do not justify. This authorization index is otherwise only
/// ever grown by `record_change_file_versions` from that same field
/// (`INSERT OR IGNORE`, additive only), so an extra relation is reachable
/// only through direct tampering or corruption — but since it is what
/// `group_file_version_references_block` consults to decide whether a
/// group's retained history justifies serving a physical block, an
/// unjustified row is a live authorization boundary, not inert metadata.
pub(crate) fn prune_unjustified_change_file_versions(
    conn: &Connection,
    change: &Change,
    change_hash: &ChangeHash,
) -> Result<(), SyncSqliteError> {
    let justified: std::collections::HashSet<Vec<u8>> =
        change.ops.iter().filter_map(op_version_hash).map(|v| v.0.to_vec()).collect();
    let recorded: Vec<Vec<u8>> = {
        let mut stmt = conn.prepare(
            "SELECT version_hash FROM change_file_versions \
             WHERE group_id = ?1 AND change_hash = ?2",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![change.group_id.as_str(), &change_hash.0[..]], |row| {
                row.get(0)
            })?;
        rows.collect::<Result<_, _>>()?
    };
    for version_hash in recorded {
        if !justified.contains(&version_hash) {
            conn.execute(
                "DELETE FROM change_file_versions \
                 WHERE group_id = ?1 AND change_hash = ?2 AND version_hash = ?3",
                rusqlite::params![change.group_id.as_str(), &change_hash.0[..], &version_hash],
            )?;
        }
    }
    Ok(())
}
