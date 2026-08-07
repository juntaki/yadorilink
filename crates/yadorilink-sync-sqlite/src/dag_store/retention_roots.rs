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
            -- life. Consumed by an owner's own orphan sweep (e.g.
            -- `yadorilink-sync-core::retained_obligation::sweep_orphaned_captured_authoring_roots`)
            -- to bound the window between a root being registered and its
            -- owning record being created, when the two happen as separate
            -- steps -- see that function's doc for why age, not just
            -- presence, is required.
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

/// Registers that `owner_kind`/`owner_id` requires `change_hash` retained at
/// `class` in `group_id`. Idempotent: registering the same root twice (the
/// ordinary case for a long-lived owner re-asserting its roots) is a no-op
/// past the first call -- including leaving `registered_at_unix_nanos` at
/// whatever the first call stamped.
///
/// Stamps `registered_at_unix_nanos` from the real wall clock rather than
/// accepting it as a parameter: every existing caller of this function
/// (`captured_authoring`, `index`) predates the orphan-sweep need for this
/// column and calls it without a timestamp, and none of them are owned by
/// this module -- threading a `now_unix_nanos` parameter through their call
/// sites is out of scope for the table this function owns. This matches the
/// same non-caller-supplied-clock shape `captured_authoring_receipts.
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

/// The block-level live set implied by every `full_payload` root registered
/// for `group_id`: every block hash referenced by a `FileVersion` that a
/// `full_payload`-rooted change's ops name, resolved through
/// `change_file_versions`/`file_versions` -- the same tables
/// `serving_authorization_index` already owns and decodes, not a
/// subsystem-private payload. Meant to be passed as (part of) the
/// `extra_roots` argument to
/// `yadorilink-sync-core::index::IndexDb::live_block_hashes_with_extra_roots`, per that
/// function's own doc comment naming `extra_roots` as the extension point
/// for exactly this.
///
/// A registered root whose change no longer decodes, or whose referenced
/// version has no retained encoding, is a corrupt-state error, not a silent
/// skip: a hash was promised full-payload retention, so its content must
/// still be resolvable, and an unresolvable root would otherwise let GC
/// silently reclaim blocks something explicitly declared it still needs.
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
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::change::{Change, ChangeAuth, Op, PutOrigin};
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_replica_domain::file::{FileMeta, VersionBlock};
    use yadorilink_replica_domain::ids::{BlockHash, DeviceId, FolderGroupId, SyncPath};

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        init_retention_roots_schema(&conn).unwrap();
        crate::dag_store::init_conflict_copy_provenance_schema(&conn).unwrap();
        crate::dag_store::init_dag_schema(&conn).unwrap();
        conn
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn make_version(byte: u8) -> FileVersion {
        let blocks = vec![VersionBlock { hash: BlockHash(vec![byte; 32]), size: 4 }];
        let meta = FileMeta {
            mtime_unix_nanos: 1,
            exec_bit: false,
            symlink_target: None,
            record_kind: RecordKind::File,
        };
        FileVersion::new(blocks, 4, meta)
    }

    #[test]
    fn register_and_release_round_trip() {
        let conn = open();
        let hash = ChangeHash([9u8; 32]);
        register_retention_root(
            &conn,
            "materialized_generation",
            "gen-1",
            "g",
            &hash,
            RetentionClass::FullPayload,
        )
        .unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM dag_retention_roots", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1);
        release_retention_root(
            &conn,
            "materialized_generation",
            "gen-1",
            "g",
            &hash,
            RetentionClass::FullPayload,
        )
        .unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM dag_retention_roots", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn registering_the_same_root_twice_is_idempotent() {
        let conn = open();
        let hash = ChangeHash([9u8; 32]);
        for _ in 0..3 {
            register_retention_root(&conn, "k", "id", "g", &hash, RetentionClass::CausalStub)
                .unwrap();
        }
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM dag_retention_roots", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn full_payload_root_resolves_to_its_referenced_block_hashes() {
        let conn = open();
        let version = make_version(0xAB);
        crate::dag_store::put_file_version(&conn, "g", &version).unwrap();
        let change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("d1".into()),
            FolderGroupId("g".into()),
            vec![Op::Put {
                path: SyncPath("a.txt".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing_key(),
        );
        crate::dag_store::admit_change(&conn, &change, false).unwrap();
        register_retention_root(
            &conn,
            "materialized_generation",
            "gen-1",
            "g",
            &change.compute_hash(),
            RetentionClass::FullPayload,
        )
        .unwrap();

        let live = full_payload_retained_block_hashes(&conn, "g").unwrap();
        assert_eq!(live, HashSet::from([hex::encode([0xABu8; 32])]));
    }

    #[test]
    fn a_group_with_no_registered_roots_yields_no_extra_live_blocks() {
        let conn = open();
        assert!(full_payload_retained_block_hashes(&conn, "g").unwrap().is_empty());
    }

    fn emitter(seed: u8) -> crate::dag_store::ChangeEmitter {
        crate::dag_store::ChangeEmitter::new(
            format!("device-{seed}"),
            SigningKey::from_bytes(&[seed; 32]),
        )
    }

    fn is_pruned(conn: &Connection, group_id: &str, hash: &ChangeHash) -> bool {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM pruned_changes WHERE group_id = ?1 AND change_hash = ?2)",
            rusqlite::params![group_id, &hash.0[..]],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// A two-change chain (`a` parented on nothing, `b` parented on `a`) with
    /// `a` registered `full_payload` -- a stand-in for `captured_authoring`'s
    /// own hand-off. A checkpoint whose plan would prune `a` (a real prune
    /// plan: `b` is the surviving frontier, `a` is strictly below it) must
    /// leave `a` fully intact -- present in `changes`, absent from
    /// `pruned_changes` -- proving `commit_prune` honors the root rather than
    /// deleting `a`'s body regardless. See [`commit_prune`]'s own doc for why
    /// this is a per-hash skip, not a whole-checkpoint refusal: `b`
    /// (unrooted, and not even in this checkpoint's `pruned` list to begin
    /// with) is untouched either way, confirming the checkpoint still
    /// commits normally around the held root.
    #[test]
    fn a_full_payload_rooted_change_survives_a_checkpoint_that_would_prune_it() {
        let conn = open();
        let em = emitter(1);
        let a = crate::dag_store::emit_local_change(
            &conn,
            "g",
            vec![Op::Put {
                path: SyncPath("a.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([1u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        let a_hash = a.compute_hash();
        let b = crate::dag_store::emit_local_change(
            &conn,
            "g",
            vec![Op::Put {
                path: SyncPath("b.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([2u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        let b_hash = b.compute_hash();

        register_retention_root(
            &conn,
            "captured_authoring",
            "retained-1",
            "g",
            &a_hash,
            RetentionClass::FullPayload,
        )
        .unwrap();

        // The real plan a compactor would compute: `b` is the maximal
        // (surviving) frontier, `a` sits strictly below it and would
        // ordinarily be pruned.
        let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
            FolderGroupId("g".into()),
            vec![b_hash],
            [0u8; 32],
        );
        crate::dag_store::commit_prune(&conn, &checkpoint, &[a_hash]).unwrap();

        assert!(
            crate::dag_store::has_change(&conn, &a_hash).unwrap(),
            "rooted change must survive"
        );
        assert!(
            !is_pruned(&conn, "g", &a_hash),
            "rooted change must not gain a pruned-stub tombstone"
        );
        assert!(
            crate::dag_store::has_change(&conn, &b_hash).unwrap(),
            "unrelated change is unaffected"
        );
    }

    /// The mirror case: once the same root is released, a later checkpoint
    /// naming the same hash actually prunes it -- proving the skip in
    /// `commit_prune` is scoped to a live root, not a permanent exemption.
    #[test]
    fn a_released_root_no_longer_blocks_pruning_the_same_change() {
        let conn = open();
        let em = emitter(2);
        let a = crate::dag_store::emit_local_change(
            &conn,
            "g",
            vec![Op::Put {
                path: SyncPath("a.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([3u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        let a_hash = a.compute_hash();
        let b = crate::dag_store::emit_local_change(
            &conn,
            "g",
            vec![Op::Put {
                path: SyncPath("b.txt".into()),
                version: yadorilink_replica_domain::ids::VersionHash([4u8; 32]),
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        let b_hash = b.compute_hash();

        register_retention_root(
            &conn,
            "captured_authoring",
            "retained-2",
            "g",
            &a_hash,
            RetentionClass::FullPayload,
        )
        .unwrap();
        let checkpoint_1 = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
            FolderGroupId("g".into()),
            vec![b_hash],
            [0u8; 32],
        );
        crate::dag_store::commit_prune(&conn, &checkpoint_1, &[a_hash]).unwrap();
        assert!(
            crate::dag_store::has_change(&conn, &a_hash).unwrap(),
            "still held by the live root"
        );

        release_retention_root(
            &conn,
            "captured_authoring",
            "retained-2",
            "g",
            &a_hash,
            RetentionClass::FullPayload,
        )
        .unwrap();
        let checkpoint_2 = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
            FolderGroupId("g".into()),
            vec![b_hash],
            [1u8; 32],
        );
        crate::dag_store::commit_prune(&conn, &checkpoint_2, &[a_hash]).unwrap();

        assert!(!crate::dag_store::has_change(&conn, &a_hash).unwrap(), "must now prune");
        assert!(is_pruned(&conn, "g", &a_hash), "must now carry a pruned-stub tombstone");
    }

    /// [`full_payload_retained_block_hashes_all_groups`] unions roots across
    /// every group in one pass -- the shape `yadorilink-daemon`'s
    /// daemon-wide GC sweep needs (one block store shared by every group).
    /// Two distinct groups each with their own rooted change and distinct
    /// block content prove neither the union nor the per-group resolution
    /// (`group_id` threaded correctly into `get_file_version`) is lost.
    #[test]
    fn all_groups_block_hashes_unions_roots_across_every_group() {
        let conn = open();
        crate::dag_store::init_dag_schema(&conn).unwrap(); // second group's schema is the same tables; idempotent
        let version_g1 = make_version(0x11);
        let version_g2 = make_version(0x22);
        crate::dag_store::put_file_version(&conn, "g1", &version_g1).unwrap();
        crate::dag_store::put_file_version(&conn, "g2", &version_g2).unwrap();

        let change_g1 = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("d1".into()),
            FolderGroupId("g1".into()),
            vec![Op::Put {
                path: SyncPath("a.txt".into()),
                version: version_g1.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing_key(),
        );
        let change_g2 = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("d2".into()),
            FolderGroupId("g2".into()),
            vec![Op::Put {
                path: SyncPath("b.txt".into()),
                version: version_g2.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing_key(),
        );
        crate::dag_store::admit_change(&conn, &change_g1, false).unwrap();
        crate::dag_store::admit_change(&conn, &change_g2, false).unwrap();
        register_retention_root(
            &conn,
            "captured_authoring",
            "retained-g1",
            "g1",
            &change_g1.compute_hash(),
            RetentionClass::FullPayload,
        )
        .unwrap();
        register_retention_root(
            &conn,
            "captured_authoring",
            "retained-g2",
            "g2",
            &change_g2.compute_hash(),
            RetentionClass::FullPayload,
        )
        .unwrap();

        let live = full_payload_retained_block_hashes_all_groups(&conn).unwrap();
        assert_eq!(
            live,
            HashSet::from([hex::encode([0x11u8; 32]), hex::encode([0x22u8; 32])]),
            "must include both groups' rooted blocks in one union"
        );
    }
}
