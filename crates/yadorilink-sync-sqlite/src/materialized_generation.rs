//! `path_materialized_generations`: the durable record of what the engine
//! believes the disk currently reflects for a path, kept separate from what
//! the change DAG resolves that path to (`DiskGenerationBasis`).
//!
//! This module is deliberately narrow: it records and reads one row per
//! `(group_id, path)`. Nothing here decides *when* a generation should
//! change -- that is a caller's job, restated here because it is easy to get
//! backwards: a new admission (desired state) must never touch this table; a
//! row here changes only after a filesystem placement has been observed
//! committed and durably recorded. `yadorilink_sync_core::optimistic_placement::
//! execute_short_commit_window_unchecked` is that caller: it writes a
//! generation in the same SQLite transaction that marks the epoch
//! `Committed`, after the platform placement and its required durability
//! flush have both succeeded; every other outcome of that window (a
//! `NotStarted`, `RequiresRecovery`, or failed-flush result) writes no
//! generation at all. `yadorilink_sync_core::index`'s
//! `backfill_materialized_generations` provides a best-effort seed for a
//! database that predates the writer, and `resolution_planning` still reads
//! the epoch journal instead of this table (see that module's own doc for
//! why).
//!
//! # Immutability
//!
//! A generation's causal basis is fixed for its lifetime: if the
//! frontier a path reflects moves, that is a *new* generation, never an
//! edit to the old one's basis. This module has exactly one write entry
//! point, [`record_materialized_generation`], and it always replaces every
//! column together under a freshly minted [`GenerationId`] -- there is no
//! "update just the basis" function to reach for by mistake. Basis
//! membership itself is even more strongly protected: interned causal
//! bases (`crate::dag_store::causal_basis`) are never mutated once written,
//! only ever referenced by a new row.
//!
//! # Absence is a generation too
//!
//! A path with nothing on disk is not "no row" -- it is a row whose
//! `object_kind` is [`MaterializedObjectKind::Absent`], `version` is
//! `None`, and `filesystem_identity` is `None`. The basis is still the
//! frontier whose resolution produced that absence (a tombstone or a
//! move-away). [`record_materialized_generation`] does not special-case
//! this: an absent generation is written through the exact same call as a
//! present one, with `object_kind: Absent`, so there is no separate path to
//! forget to handle it on.
//!
//! # History
//!
//! Split out of `yadorilink-sync-core::materialized_generation` in two
//! steps. Phase 7D-7.2 hoisted the `FileIdentity` binary codec and
//! `GenerationId` (dag_store-independent) into this crate's
//! [`crate::file_identity_codec`], since `filesystem_transaction`'s epoch
//! rows reuse that exact encoding; `record_materialized_generation`/
//! `lookup_materialized_generation` (this module) stayed behind because
//! they call `dag_store::intern_causal_basis`, and `dag_store` had not
//! moved into this crate yet. Phase 7D-7.5 finished the hoist: `dag_store`
//! landed in this crate in Phase 7D-7.3, removing that blocker, so the rest
//! of the module (this file) followed. `yadorilink-sync-core`'s
//! `materialized_generation` module now re-exports everything here (and
//! everything in `file_identity_codec`) under its old names, so its ~10
//! existing in-crate consumers did not need their `use` paths touched.

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::dag_store::intern_causal_basis;
use crate::error::SyncSqliteError;
use crate::file_identity_codec::{
    decode_file_identity, encode_file_identity, GenerationId,
    MATERIALIZED_GENERATION_ENCODING_VERSION,
};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_root_authority::fs_identity::FileIdentity;

/// `pub`, not `pub(crate)`: exposed to `yadorilink-sync-core` (this crate's
/// re-export shim, and that crate's own tests that build a full-schema
/// in-memory database) the same way `dag_store::init_dag_schema` already is.
pub fn init_materialized_generation_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS path_materialized_generations (
            group_id                   TEXT NOT NULL,
            path                       TEXT NOT NULL,
            generation_id              TEXT NOT NULL,
            causal_basis_id            TEXT NOT NULL,
            resolved_path_state_hash   BLOB NOT NULL,
            object_kind                TEXT NOT NULL,
            version_hash               BLOB,
            filesystem_identity        BLOB,
            metadata_fingerprint       BLOB,
            hardlink_group_id          TEXT,
            encoding_version           INTEGER NOT NULL,
            updated_at_unix_nanos      INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );
        "#,
    )?;
    Ok(())
}

/// The id [`crate::dag_store::intern_causal_basis`] returns, wrapped so a
/// `GenerationId` and a `CausalBasisId` -- both opaque strings -- cannot be
/// swapped positionally without a type error.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CausalBasisId(pub String);

/// What a materialized generation's path currently names. [`Absent`] is a
/// real, first-class member here -- see the module doc's "Absence is a
/// generation too" section -- not represented by `Option::None` at this
/// level, because the row itself is never optional.
///
/// [`Absent`]: MaterializedObjectKind::Absent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializedObjectKind {
    RegularFile,
    Directory,
    Symlink,
    Absent,
}

impl MaterializedObjectKind {
    fn as_db_str(self) -> &'static str {
        match self {
            MaterializedObjectKind::RegularFile => "regular_file",
            MaterializedObjectKind::Directory => "directory",
            MaterializedObjectKind::Symlink => "symlink",
            MaterializedObjectKind::Absent => "absent",
        }
    }

    fn from_db_str(value: &str) -> Result<MaterializedObjectKind, SyncSqliteError> {
        match value {
            "regular_file" => Ok(MaterializedObjectKind::RegularFile),
            "directory" => Ok(MaterializedObjectKind::Directory),
            "symlink" => Ok(MaterializedObjectKind::Symlink),
            "absent" => Ok(MaterializedObjectKind::Absent),
            other => Err(SyncSqliteError::CorruptState(format!(
                "unknown materialized_object_kind {other:?} in path_materialized_generations"
            ))),
        }
    }
}

/// One row of `path_materialized_generations`, read back. Mirrors the
/// design's `DiskGenerationBasis` exactly; `group_id`/`path` are the row's
/// key and are passed alongside this rather than duplicated inside it.
#[derive(Debug, Clone, PartialEq)]
pub struct DiskGenerationBasis {
    pub generation_id: GenerationId,
    pub causal_basis_id: CausalBasisId,
    pub resolved_path_state_hash: [u8; 32],
    pub object_kind: MaterializedObjectKind,
    pub version: Option<VersionHash>,
    pub filesystem_identity: Option<FileIdentity>,
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_str(buf: &mut Vec<u8>, value: &str) {
    put_u32(buf, value.len() as u32);
    buf.extend_from_slice(value.as_bytes());
}

const RESOLVED_PATH_STATE_DOMAIN_TAG: &[u8; 8] = b"YLNKrps\x01";

fn object_kind_tag(kind: MaterializedObjectKind) -> u8 {
    match kind {
        MaterializedObjectKind::RegularFile => 0,
        MaterializedObjectKind::Directory => 1,
        MaterializedObjectKind::Symlink => 2,
        MaterializedObjectKind::Absent => 3,
    }
}

/// The canonical encoding `resolved_path_state_hash` is derived from. This
/// is the reference definition: nothing in this crate computes a
/// desired-state `resolved_path_state_hash` yet (the resolver that turns a
/// DAG frontier into a desired target is not built), so whichever later
/// phase builds it must produce byte-identical input for the two hashes to
/// ever be comparable, and this function is where that shape lives.
fn canonical_resolved_path_state_encoding(
    group_id: &str,
    path: &str,
    object_kind: MaterializedObjectKind,
    version: Option<&VersionHash>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(RESOLVED_PATH_STATE_DOMAIN_TAG);
    put_str(&mut buf, group_id);
    put_str(&mut buf, path);
    buf.push(object_kind_tag(object_kind));
    match version {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.0);
        }
        None => buf.push(0),
    }
    buf
}

/// Hashes what a path resolves to -- its kind and, when it has one, its
/// version -- independent of which causal frontier produced that
/// resolution. Two different bases that happen to resolve to the same
/// object and version hash to the same value on purpose: that is what lets
/// a future comparison ask "does disk match desired?" without caring which
/// route either side took to get there.
pub fn compute_resolved_path_state_hash(
    group_id: &str,
    path: &str,
    object_kind: MaterializedObjectKind,
    version: Option<&VersionHash>,
) -> [u8; 32] {
    Sha256::digest(canonical_resolved_path_state_encoding(group_id, path, object_kind, version))
        .into()
}

fn new_generation_id(group_id: &str) -> GenerationId {
    let random: [u8; 16] = rand::random();
    GenerationId(format!("{group_id}:{}", hex::encode(random)))
}

/// Records a new materialized generation for `(group_id, path)`. Always
/// replaces the row wholesale under a freshly minted [`GenerationId`] --
/// see the module doc's immutability section for why there is no separate
/// "update the basis" entry point. `causal_basis` is the complete frontier
/// this generation reflects; it is interned via
/// [`crate::dag_store::intern_causal_basis`], so a path sharing a frontier
/// with a million others shares one basis row, not a million copies.
///
/// `object_kind: Absent` and `version: None`/`filesystem_identity: None`
/// together record an absent path's generation -- there is no separate
/// function for that case; see the module doc.
#[allow(clippy::too_many_arguments)]
pub fn record_materialized_generation(
    conn: &Connection,
    group_id: &str,
    path: &str,
    causal_basis: &[ChangeHash],
    object_kind: MaterializedObjectKind,
    version: Option<&VersionHash>,
    filesystem_identity: Option<&FileIdentity>,
    now_unix_nanos: i64,
) -> Result<DiskGenerationBasis, SyncSqliteError> {
    let causal_basis_id = CausalBasisId(intern_causal_basis(conn, group_id, causal_basis)?);
    let resolved_path_state_hash =
        compute_resolved_path_state_hash(group_id, path, object_kind, version);
    let generation_id = new_generation_id(group_id);
    let filesystem_identity_blob = filesystem_identity.map(encode_file_identity);
    let metadata_fingerprint_blob = filesystem_identity.map(|id| id.metadata_fingerprint.to_vec());
    let version_blob = version.map(|v| v.0.to_vec());

    conn.execute(
        "INSERT INTO path_materialized_generations
            (group_id, path, generation_id, causal_basis_id, resolved_path_state_hash,
             object_kind, version_hash, filesystem_identity, metadata_fingerprint,
             hardlink_group_id, encoding_version, updated_at_unix_nanos)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11)
         ON CONFLICT (group_id, path) DO UPDATE SET
            generation_id = excluded.generation_id,
            causal_basis_id = excluded.causal_basis_id,
            resolved_path_state_hash = excluded.resolved_path_state_hash,
            object_kind = excluded.object_kind,
            version_hash = excluded.version_hash,
            filesystem_identity = excluded.filesystem_identity,
            metadata_fingerprint = excluded.metadata_fingerprint,
            hardlink_group_id = NULL,
            encoding_version = excluded.encoding_version,
            updated_at_unix_nanos = excluded.updated_at_unix_nanos",
        rusqlite::params![
            group_id,
            path,
            generation_id.0,
            causal_basis_id.0,
            &resolved_path_state_hash[..],
            object_kind.as_db_str(),
            version_blob,
            filesystem_identity_blob,
            metadata_fingerprint_blob,
            MATERIALIZED_GENERATION_ENCODING_VERSION,
            now_unix_nanos,
        ],
    )?;

    Ok(DiskGenerationBasis {
        generation_id,
        causal_basis_id,
        resolved_path_state_hash,
        object_kind,
        version: version.copied(),
        filesystem_identity: filesystem_identity.copied(),
    })
}

/// Reads back the current materialized generation for `(group_id, path)`,
/// or `None` if this path has never had one recorded.
pub fn lookup_materialized_generation(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<DiskGenerationBasis>, SyncSqliteError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(String, String, Vec<u8>, String, Option<Vec<u8>>, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT generation_id, causal_basis_id, resolved_path_state_hash, object_kind, \
                    version_hash, filesystem_identity \
             FROM path_materialized_generations WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()?;
    let Some((generation_id, causal_basis_id, hash_blob, kind_str, version_blob, identity_blob)) =
        row
    else {
        return Ok(None);
    };
    let resolved_path_state_hash: [u8; 32] = hash_blob.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "invalid resolved_path_state_hash length for {group_id}/{path}"
        ))
    })?;
    let object_kind = MaterializedObjectKind::from_db_str(&kind_str)?;
    let version = version_blob
        .map(|bytes| {
            let hash: [u8; 32] = bytes.try_into().map_err(|_| {
                SyncSqliteError::CorruptState(format!(
                    "invalid version_hash length for {group_id}/{path}"
                ))
            })?;
            Ok::<_, SyncSqliteError>(VersionHash(hash))
        })
        .transpose()?;
    let filesystem_identity =
        identity_blob.map(|bytes| decode_file_identity(&bytes)).transpose()?;
    Ok(Some(DiskGenerationBasis {
        generation_id: GenerationId(generation_id),
        causal_basis_id: CausalBasisId(causal_basis_id),
        resolved_path_state_hash,
        object_kind,
        version,
        filesystem_identity,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_root_authority::fs_identity::{
        ObjectKind, PlatformObjectId, Timestamp, VolumeIdentity,
    };

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::dag_store::init_dag_schema(&conn).unwrap();
        init_materialized_generation_schema(&conn).unwrap();
        conn
    }

    fn h(byte: u8) -> ChangeHash {
        ChangeHash([byte; 32])
    }

    fn sample_identity() -> FileIdentity {
        FileIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: 7 },
            object_id: PlatformObjectId::Unix { inode: 42 },
            object_kind: ObjectKind::RegularFile,
            generation_or_usn: Some(3),
            birth_or_creation_time: Some(Timestamp {
                seconds_since_unix_epoch: 1_700_000_000,
                subsec_nanos: 123,
            }),
            observed_size: 1024,
            metadata_fingerprint: [9; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        }
    }

    #[test]
    fn a_new_generation_can_be_looked_up_back_exactly() {
        let conn = open();
        let version = VersionHash([5; 32]);
        let identity = sample_identity();
        let written = record_materialized_generation(
            &conn,
            "g",
            "a.txt",
            &[h(1), h(2)],
            MaterializedObjectKind::RegularFile,
            Some(&version),
            Some(&identity),
            1000,
        )
        .unwrap();
        let read = lookup_materialized_generation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(read, written);
        assert_eq!(read.version, Some(version));
        assert_eq!(read.filesystem_identity, Some(identity));
    }

    #[test]
    fn an_absent_path_is_recorded_as_its_own_object_kind_not_a_missing_row() {
        let conn = open();
        record_materialized_generation(
            &conn,
            "g",
            "gone.txt",
            &[h(9)],
            MaterializedObjectKind::Absent,
            None,
            None,
            1000,
        )
        .unwrap();
        let read = lookup_materialized_generation(&conn, "g", "gone.txt").unwrap().unwrap();
        assert_eq!(read.object_kind, MaterializedObjectKind::Absent);
        assert!(read.version.is_none());
        assert!(read.filesystem_identity.is_none());
    }

    #[test]
    fn lookup_of_a_never_recorded_path_is_none() {
        let conn = open();
        assert!(lookup_materialized_generation(&conn, "g", "never.txt").unwrap().is_none());
    }

    #[test]
    fn recording_a_new_generation_replaces_the_row_under_a_fresh_id_not_in_place() {
        // The immutability rule: a later generation is a NEW row under a
        // new id, never an edit of the old basis in place. Proven
        // here by writing two different bases at the same path and
        // confirming the second call's `generation_id` differs from the
        // first's, and that a lookup only ever sees the latest, complete
        // row -- never a hybrid of the two.
        let conn = open();
        let first = record_materialized_generation(
            &conn,
            "g",
            "a.txt",
            &[h(1)],
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([1; 32])),
            None,
            1000,
        )
        .unwrap();
        let second = record_materialized_generation(
            &conn,
            "g",
            "a.txt",
            &[h(2)],
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([2; 32])),
            None,
            2000,
        )
        .unwrap();
        assert_ne!(first.generation_id, second.generation_id);
        assert_ne!(first.causal_basis_id, second.causal_basis_id);
        let read = lookup_materialized_generation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(read, second, "must read back exactly the latest generation, not a merge");
    }

    #[test]
    fn a_million_paths_sharing_one_frontier_intern_one_basis_row() {
        let conn = open();
        for i in 0..1000 {
            record_materialized_generation(
                &conn,
                "g",
                &format!("path-{i}.txt"),
                &[h(1), h(2)],
                MaterializedObjectKind::RegularFile,
                Some(&VersionHash([1; 32])),
                None,
                1000,
            )
            .unwrap();
        }
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM causal_basis_sets", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "1000 paths sharing one frontier must intern to one basis row");
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM path_materialized_generations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1000, "each path still gets its own generation row");
    }

    #[test]
    fn different_paths_with_the_same_content_share_a_resolved_path_state_hash_only_if_the_path_matches(
    ) {
        // `resolved_path_state_hash` is keyed by path (a symlink named `a`
        // pointing at content X is not interchangeable with one named `b`
        // pointing at the same content) -- confirmed here as a property of
        // the hash itself, not the table.
        let a = compute_resolved_path_state_hash(
            "g",
            "a.txt",
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([1; 32])),
        );
        let b = compute_resolved_path_state_hash(
            "g",
            "b.txt",
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([1; 32])),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn resolved_path_state_hash_distinguishes_absent_from_every_present_kind() {
        let absent =
            compute_resolved_path_state_hash("g", "a", MaterializedObjectKind::Absent, None);
        let file = compute_resolved_path_state_hash(
            "g",
            "a",
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([1; 32])),
        );
        let dir =
            compute_resolved_path_state_hash("g", "a", MaterializedObjectKind::Directory, None);
        assert_ne!(absent, file);
        assert_ne!(absent, dir);
    }
}
