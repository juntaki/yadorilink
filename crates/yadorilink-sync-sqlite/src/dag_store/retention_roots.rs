//! `dag_retention_roots`: one shared table any subsystem registers an exact
//! retained change hash into, stating who registered it and why.
//!
//! The whole point of a *shared* table is that compaction never has to
//! decode a subsystem-specific payload to learn what it must not evict --
//! every consumer names the exact hash it needs kept, in one common
//! `(owner_kind, owner_id, group_id, change_hash, retention_class)` shape.
//! [`full_payload_retained_block_hashes`] resolves the `full_payload` class
//! down to the block-level live set through machinery this crate already
//! owns and already decodes for other reasons (`change_file_versions` and
//! `file_versions`, exactly as `serving_authorization_index` uses them) --
//! it does not reach into any owner's own private record to do so.

use std::collections::HashSet;

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::ChangeHash;

/// Why a registered change hash must not be evicted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionClass {
    /// Operations, file versions, provenance and referenced blocks must all
    /// stay retained -- compaction must not even reduce this change to a
    /// causal stub.
    FullPayload,
    /// Only the authenticated header, author identity, Lamport clock and
    /// parent edges need to survive; operations and block payload may be
    /// dropped.
    CausalStub,
}

impl RetentionClass {
    fn as_str(self) -> &'static str {
        match self {
            RetentionClass::FullPayload => "full_payload",
            RetentionClass::CausalStub => "causal_stub",
        }
    }
}

pub(crate) fn init_retention_roots_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS dag_retention_roots (
            owner_kind       TEXT NOT NULL,
            owner_id         TEXT NOT NULL,
            group_id         TEXT NOT NULL,
            change_hash      BLOB NOT NULL,
            retention_class  TEXT NOT NULL,
            -- When this row was first inserted (real wall clock, stamped by
            -- `register_retention_root` itself -- see that function's doc).
            -- `INSERT OR IGNORE` never updates it on a re-registration, so it
            -- is the true first-registration instant for the row's whole
            -- life. An owner's orphan sweep uses it to bound the window
            -- between a root being registered and its owning record being
            -- created, when the two happen as separate steps: age, not mere
            -- presence, is what distinguishes an in-flight pair from a
            -- stranded root.
            registered_at_unix_nanos INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (owner_kind, owner_id, group_id, change_hash, retention_class)
        );
        CREATE INDEX IF NOT EXISTS dag_retention_roots_by_change
            ON dag_retention_roots(group_id, change_hash, retention_class);
        CREATE INDEX IF NOT EXISTS dag_retention_roots_by_owner
            ON dag_retention_roots(owner_kind, group_id);
        "#,
    )?;
    Ok(())
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Registers that `owner_kind`/`owner_id` requires `change_hash` retained
/// at `class` in `group_id`. Idempotent: registering the same root twice
/// (the ordinary case for a long-lived owner re-asserting its roots) is a
/// no-op past the first call -- including leaving
/// `registered_at_unix_nanos` at whatever the first call stamped.
/// created_at_unix_nanos` already uses for its own "when was this durable
/// row first written" column.
pub fn register_retention_root(
    conn: &Connection,
    owner_kind: &str,
    owner_id: &str,
    group_id: &str,
    change_hash: &ChangeHash,
    class: RetentionClass,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "INSERT OR IGNORE INTO dag_retention_roots \
         (owner_kind, owner_id, group_id, change_hash, retention_class, registered_at_unix_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            owner_kind,
            owner_id,
            group_id,
            &change_hash.0[..],
            class.as_str(),
            now_unix_nanos(),
        ],
    )?;
    Ok(())
}

/// Releases a previously registered root. Compaction must never infer that a
/// hash is unretained merely because ONE owner released it -- callers other
/// than the owner that registered it must not call this.
pub fn release_retention_root(
    conn: &Connection,
    owner_kind: &str,
    owner_id: &str,
    group_id: &str,
    change_hash: &ChangeHash,
    class: RetentionClass,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "DELETE FROM dag_retention_roots \
         WHERE owner_kind = ?1 AND owner_id = ?2 AND group_id = ?3 \
           AND change_hash = ?4 AND retention_class = ?5",
        rusqlite::params![owner_kind, owner_id, group_id, &change_hash.0[..], class.as_str()],
    )?;
    Ok(())
}

/// Every distinct change hash any owner has registered at `full_payload` for
/// `group_id`, regardless of which owner(s) registered it.
fn full_payload_root_change_hashes(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT change_hash FROM dag_retention_roots \
         WHERE group_id = ?1 AND retention_class = ?2",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![group_id, RetentionClass::FullPayload.as_str()], |row| {
            row.get::<_, Vec<u8>>(0)
        })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(super::retained_history_integrity::hash_from_blob(row?)?);
    }
    Ok(out)
}

/// The block-level live set implied by every `full_payload` root
/// registered for `group_id`: every block hash referenced by a
/// `FileVersion` that a `full_payload`-rooted change's ops name, resolved
/// through `change_file_versions`/`file_versions` -- the same tables
/// `serving_authorization_index` already owns and decodes, not a
/// subsystem-private payload. A registered root whose change no longer
/// decodes, or whose referenced version has no retained encoding, is a
/// corrupt-state error, not a silent skip: a hash was promised
/// full-payload retention, so its content must still be resolvable, and an
/// unresolvable root would otherwise let GC silently reclaim blocks
/// something explicitly declared it still needs.
pub fn full_payload_retained_block_hashes(
    conn: &Connection,
    group_id: &str,
) -> Result<HashSet<String>, SyncSqliteError> {
    let mut live = HashSet::new();
    for change_hash in full_payload_root_change_hashes(conn, group_id)? {
        live.extend(resolve_full_payload_root_blocks(conn, group_id, &change_hash)?);
    }
    Ok(live)
}

/// One `full_payload` root's own resolution: decode the retained change,
/// walk its ops, and return every block hash its referenced `FileVersion`s
/// name. Factored out of [`full_payload_retained_block_hashes`] so
/// [`full_payload_retained_block_hashes_all_groups`] applies the identical
/// resolution and fail-closed rules per `(group_id, change_hash)` pair
/// instead of duplicating them.
fn resolve_full_payload_root_blocks(
    conn: &Connection,
    group_id: &str,
    change_hash: &ChangeHash,
) -> Result<HashSet<String>, SyncSqliteError> {
    let mut live = HashSet::new();
    let Some(encoded) = super::retained_history_integrity::get_encoded(conn, change_hash)? else {
        return Err(SyncSqliteError::CorruptState(format!(
            "dag retention root {} is registered full_payload for group {group_id} but the \
             change no longer has a retained body",
            change_hash.to_hex(),
        )));
    };
    let change =
        yadorilink_replica_domain::change::Change::from_wire_bytes(&encoded).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "dag retention root {} for group {group_id} no longer decodes: {error}",
                change_hash.to_hex(),
            ))
        })?;
    for op in &change.ops {
        let Some(version_hash) = op_version_hash(op) else { continue };
        let Some(version) =
            super::serving_authorization_index::get_file_version(conn, group_id, version_hash)?
        else {
            return Err(SyncSqliteError::CorruptState(format!(
                "dag retention root {} for group {group_id} references version {} with no \
                 retained encoding",
                change_hash.to_hex(),
                version_hash.to_hex(),
            )));
        };
        live.extend(block_hashes_of(&version));
    }
    Ok(live)
}

/// Which of `candidates` currently carry a `full_payload` root for
/// `group_id` -- the set [`crate::dag_store::commit_prune`] must not reduce
/// to a causal stub, per [`RetentionClass::FullPayload`]'s own contract
/// ("compaction must not even reduce this change to a causal stub"). A plain
/// per-hash membership query against the shared table, not a decode of any
/// owner's private state, matching this table's whole reason for existing.
pub(crate) fn full_payload_rooted(
    conn: &Connection,
    group_id: &str,
    candidates: &[ChangeHash],
) -> Result<HashSet<ChangeHash>, SyncSqliteError> {
    let mut rooted = HashSet::new();
    let mut stmt = conn.prepare(
        "SELECT 1 FROM dag_retention_roots \
         WHERE group_id = ?1 AND change_hash = ?2 AND retention_class = ?3 LIMIT 1",
    )?;
    for hash in candidates {
        let found = stmt
            .query_row(
                rusqlite::params![group_id, &hash.0[..], RetentionClass::FullPayload.as_str()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if found {
            rooted.insert(*hash);
        }
    }
    Ok(rooted)
}

/// Every distinct `(group_id, change_hash)` any owner has registered at
/// `full_payload`, across every group -- the daemon-wide counterpart of
/// [`full_payload_root_change_hashes`], for a caller (physical block-store
/// GC) that sweeps every group in one pass rather than one group at a time.
fn all_full_payload_roots(conn: &Connection) -> Result<Vec<(String, ChangeHash)>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT group_id, change_hash FROM dag_retention_roots WHERE retention_class = ?1",
    )?;
    let rows = stmt.query_map(rusqlite::params![RetentionClass::FullPayload.as_str()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (group_id, hash_bytes) = row?;
        out.push((group_id, super::retained_history_integrity::hash_from_blob(hash_bytes)?));
    }
    Ok(out)
}

/// The block-level live set implied by every `full_payload` root registered
/// in this store, across every group -- the daemon-wide counterpart of
/// [`full_payload_retained_block_hashes`]. Physical block-store GC
/// (`yadorilink-daemon`'s sweep) is one process-wide pass over one block
/// store shared by every group, so it needs this union rather than a
/// per-group call; see that function's own doc for the resolution and
/// fail-closed rules, applied identically here per `(group_id, change_hash)`
/// pair.
pub fn full_payload_retained_block_hashes_all_groups(
    conn: &Connection,
) -> Result<HashSet<String>, SyncSqliteError> {
    let mut live = HashSet::new();
    for (group_id, change_hash) in all_full_payload_roots(conn)? {
        live.extend(resolve_full_payload_root_blocks(conn, &group_id, &change_hash)?);
    }
    Ok(live)
}

fn op_version_hash(
    op: &yadorilink_replica_domain::change::Op,
) -> Option<&yadorilink_replica_domain::ids::VersionHash> {
    match op {
        yadorilink_replica_domain::change::Op::Put { version, .. }
        | yadorilink_replica_domain::change::Op::Move { version, .. } => Some(version),
        yadorilink_replica_domain::change::Op::Delete { .. } => None,
    }
}

fn block_hashes_of(version: &FileVersion) -> impl Iterator<Item = String> + '_ {
    version.blocks.iter().map(|block| hex::encode(&block.hash.0))
}

#[cfg(test)]
mod tests;
