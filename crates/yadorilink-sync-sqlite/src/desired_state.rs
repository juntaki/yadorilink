//! C4-12 Stage 1: the *desired*-side half of the resolved-state comparison
//! `materialized_generation`'s own doc comment says nothing in this crate
//! computes yet. `compute_resolved_path_state_hash` is already a complete,
//! reusable hash of "what a path resolves to" -- it does not depend on
//! causal basis or filesystem identity, by design. What is missing is only
//! the *input* to it: turning a [`PathResolution`] (the DAG-level winner for
//! one path) into the `(MaterializedObjectKind, Option<VersionHash>)` pair
//! that hash function needs.
//!
//! Lives here, not in `yadorilink-replica-engine` (which owns
//! `PathResolution`/`resolve_path_heads`): this crate depends on
//! `yadorilink-replica-engine`, not the reverse, and `MaterializedObjectKind`/
//! `compute_resolved_path_state_hash`/`get_file_version` all live here. A
//! builder that calls all of them therefore belongs on this side of the
//! dependency edge.

use rusqlite::Connection;

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_engine::conflict::PathResolution;

use crate::dag_store::get_file_version;
use crate::error::SyncSqliteError;
use crate::materialized_generation::{compute_resolved_path_state_hash, MaterializedObjectKind};

fn map_record_kind(kind: RecordKind) -> MaterializedObjectKind {
    match kind {
        RecordKind::File => MaterializedObjectKind::RegularFile,
        RecordKind::Directory => MaterializedObjectKind::Directory,
        RecordKind::Symlink => MaterializedObjectKind::Symlink,
    }
}

/// Computes the desired-side `resolved_path_state_hash` for one path, given
/// the outcome of `resolve_path_heads` and the winning head's content
/// version. `resolve_path_heads` takes `&[PathHead]` and returns `winner` as
/// an index into it, so the caller already has the winning head (and its
/// `version_hash`) in hand at the point it calls this -- this function takes
/// that version hash directly rather than re-deriving it from `resolution`
/// and a `heads` slice, so it has no dependency on the caller's own
/// `PathHead` storage shape. No new hash shape: this calls the existing
/// `compute_resolved_path_state_hash` directly.
///
/// `PathResolution::Absent` -> `(MaterializedObjectKind::Absent, None)`.
/// `PathResolution::Present` -> looks up `winner_version_hash` via
/// [`get_file_version`] (already fail-closed: re-verifies the decoded
/// content's own hash against the request) to read the version's
/// [`RecordKind`], maps it to [`MaterializedObjectKind`], and hashes
/// `(object_kind, Some(winner_version_hash))`.
///
/// Returns [`SyncSqliteError::NotFound`] (via `get_file_version`'s own
/// fail-closed contract, or directly if the caller omits `winner_version_
/// hash` for a `Present` resolution) rather than ever collapsing an
/// unresolvable winner to `Absent`: a worker with no local record of the
/// winning file version cannot honestly say what the path resolves to, and
/// reporting `Absent` would let a real desired-state hash collide with the
/// one genuinely-absent state a tombstoned path also hashes to. The correct
/// reading of this error is "not yet resolvable" (the content index for
/// this version has not arrived locally yet) -- a caller should defer/retry
/// on it, never close an obligation against `MaterializedObjectKind::
/// Absent` because of it.
pub fn desired_resolved_path_state_hash(
    conn: &Connection,
    group_id: &str,
    path: &str,
    resolution: &PathResolution,
    winner_version_hash: Option<&VersionHash>,
) -> Result<[u8; 32], SyncSqliteError> {
    match resolution {
        PathResolution::Absent => Ok(compute_resolved_path_state_hash(
            group_id,
            path,
            MaterializedObjectKind::Absent,
            None,
        )),
        PathResolution::Present { .. } => {
            let version_hash = winner_version_hash.ok_or_else(|| {
                SyncSqliteError::NotFound(format!(
                    "resolve_path_heads reported {path} as Present but no winning version hash \
                     was supplied"
                ))
            })?;
            let version = get_file_version(conn, group_id, version_hash)?.ok_or_else(|| {
                SyncSqliteError::NotFound(format!(
                    "winning version {} for {path} is not locally resolvable",
                    version_hash.to_hex()
                ))
            })?;
            let object_kind = map_record_kind(version.meta.record_kind);
            Ok(compute_resolved_path_state_hash(group_id, path, object_kind, Some(version_hash)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind as RK, VersionBlock};
    use yadorilink_replica_domain::ids::BlockHash;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::dag_store::init_dag_schema(&c).unwrap();
        c
    }

    fn version_meta(record_kind: RK) -> FileMeta {
        FileMeta {
            mtime_unix_nanos: 1_700_000_000_000_000_000,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind,
            xattrs: Vec::new(),
        }
    }

    fn sha256(bytes: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes).to_vec()
    }

    /// Stores a version and returns its (auto-derived) `version_hash`.
    /// `File` gets one block matching `content`'s own bytes; `Directory`/
    /// `Symlink` carry no content blocks, matching `FileVersion::
    /// validate_blocks`'s own shape rule.
    fn put_version(conn: &Connection, group_id: &str, content: &[u8], kind: RK) -> VersionHash {
        let blocks = match kind {
            RK::File if !content.is_empty() => {
                vec![VersionBlock { hash: BlockHash(sha256(content)), size: content.len() as u32 }]
            }
            _ => Vec::new(),
        };
        let version = FileVersion::new(blocks, content.len() as u64, version_meta(kind));
        crate::dag_store::put_file_version(conn, group_id, &version).unwrap();
        version.version_hash
    }

    #[test]
    fn absent_resolution_hashes_the_same_as_a_materialized_absent_generation() {
        let conn = conn();
        let desired =
            desired_resolved_path_state_hash(&conn, "g", "a.txt", &PathResolution::Absent, None)
                .unwrap();
        let actual =
            compute_resolved_path_state_hash("g", "a.txt", MaterializedObjectKind::Absent, None);
        assert_eq!(
            desired, actual,
            "desired-side Absent hash must match the existing materialized-side hash exactly"
        );
    }

    #[test]
    fn present_resolution_matches_the_hash_a_real_materialized_generation_would_record() {
        let conn = conn();
        let version_hash = put_version(&conn, "g", b"hello world", RK::File);
        let resolution = PathResolution::Present { winner: 0, conflict_copies: vec![] };
        let desired =
            desired_resolved_path_state_hash(&conn, "g", "a.txt", &resolution, Some(&version_hash))
                .unwrap();
        let actual = compute_resolved_path_state_hash(
            "g",
            "a.txt",
            MaterializedObjectKind::RegularFile,
            Some(&version_hash),
        );
        assert_eq!(
            desired, actual,
            "desired-side Present hash must match compute_resolved_path_state_hash exactly for \
             the same content"
        );
    }

    #[test]
    fn a_directory_winner_maps_to_the_directory_object_kind() {
        let conn = conn();
        let version_hash = put_version(&conn, "g", b"", RK::Directory);
        let resolution = PathResolution::Present { winner: 0, conflict_copies: vec![] };
        let desired =
            desired_resolved_path_state_hash(&conn, "g", "d", &resolution, Some(&version_hash))
                .unwrap();
        let actual = compute_resolved_path_state_hash(
            "g",
            "d",
            MaterializedObjectKind::Directory,
            Some(&version_hash),
        );
        assert_eq!(desired, actual);
    }

    #[test]
    fn different_winning_content_produces_different_hashes() {
        let conn = conn();
        let v1 = put_version(&conn, "g", b"one", RK::File);
        let v2 = put_version(&conn, "g", b"two", RK::File);
        let resolution = PathResolution::Present { winner: 0, conflict_copies: vec![] };
        let h1 =
            desired_resolved_path_state_hash(&conn, "g", "a.txt", &resolution, Some(&v1)).unwrap();
        let h2 =
            desired_resolved_path_state_hash(&conn, "g", "a.txt", &resolution, Some(&v2)).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn present_and_absent_never_collide() {
        let conn = conn();
        let version_hash = put_version(&conn, "g", b"content", RK::File);
        let resolution = PathResolution::Present { winner: 0, conflict_copies: vec![] };
        let present =
            desired_resolved_path_state_hash(&conn, "g", "a.txt", &resolution, Some(&version_hash))
                .unwrap();
        let absent =
            desired_resolved_path_state_hash(&conn, "g", "a.txt", &PathResolution::Absent, None)
                .unwrap();
        assert_ne!(present, absent);
    }

    #[test]
    fn a_winning_version_not_locally_resolvable_is_a_hard_error_not_absent() {
        let conn = conn();
        let never_stored = VersionHash([7; 32]);
        let resolution = PathResolution::Present { winner: 0, conflict_copies: vec![] };
        let error =
            desired_resolved_path_state_hash(&conn, "g", "a.txt", &resolution, Some(&never_stored))
                .expect_err("an unresolvable winning version must be a hard error");
        assert!(matches!(error, SyncSqliteError::NotFound(_)));
    }

    #[test]
    fn a_present_resolution_with_no_supplied_version_hash_is_a_hard_error() {
        // Guards against a caller forgetting to pass the winner's version --
        // this must fail closed exactly like an unresolvable version, never
        // silently treat "no hash supplied" as absent.
        let conn = conn();
        let resolution = PathResolution::Present { winner: 0, conflict_copies: vec![] };
        let error = desired_resolved_path_state_hash(&conn, "g", "a.txt", &resolution, None)
            .expect_err("a Present resolution with no version hash must be a hard error");
        assert!(matches!(error, SyncSqliteError::NotFound(_)));
    }
}
