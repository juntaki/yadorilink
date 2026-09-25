#![cfg(test)]

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
    // A directory's only valid version is the canonical one (size and
    // mtime 0), so it is not built from the file-shaped metadata above.
    let version = match kind {
        RK::Directory => FileVersion::directory(version_meta(kind).unix_mode),
        _ => FileVersion::new(blocks, content.len() as u64, version_meta(kind)),
    };
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
    let h1 = desired_resolved_path_state_hash(&conn, "g", "a.txt", &resolution, Some(&v1)).unwrap();
    let h2 = desired_resolved_path_state_hash(&conn, "g", "a.txt", &resolution, Some(&v2)).unwrap();
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

// The namespace-aware desired state: a path's heads with the tree
// constraint applied.

mod namespace {
    use super::*;
    use crate::dag_store::{emit_local_change, ChangeEmitter};
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::change::{Op, PutOrigin};
    use yadorilink_replica_domain::ids::SyncPath;
    use yadorilink_replica_engine::namespace::Placement;

    fn emitter() -> ChangeEmitter {
        ChangeEmitter::new("device-A", SigningKey::from_bytes(&[42u8; 32]))
    }

    fn put(path: &str, version: VersionHash) -> Op {
        Op::Put { path: SyncPath(path.into()), version, origin: PutOrigin::Direct }
    }

    fn delete(path: &str) -> Op {
        Op::Delete { path: SyncPath(path.into()) }
    }

    /// A File `a` and a live `a/x` cannot both be on disk. `a` has to be a
    /// directory, and the file's content moves aside to its copy name: the
    /// state required at `a` is not the file.
    #[test]
    fn desired_state_of_file_a_with_live_a_slash_x_is_not_regular_file() {
        let conn = conn();
        let file_a = put_version(&conn, "g", b"a as a file", RK::File);
        let file_x = put_version(&conn, "g", b"x below a", RK::File);
        emit_local_change(&conn, "g", vec![put("a", file_a)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![put("a/x", file_x)], &emitter()).unwrap();

        let state = desired_path_state(&conn, "g", "a").unwrap();
        assert_eq!(state, DesiredPathState::StructuralDirectory);
        let hash = desired_projected_path_state_hash(&conn, "g", "a").unwrap();
        assert_ne!(
            hash,
            compute_resolved_path_state_hash(
                "g",
                "a",
                MaterializedObjectKind::RegularFile,
                Some(&file_a)
            )
        );
        assert_eq!(
            hash,
            compute_resolved_path_state_hash(
                "g",
                "a",
                MaterializedObjectKind::StructuralDirectory,
                None
            )
        );
        assert_eq!(
            desired_path_state(&conn, "g", "a/x").unwrap(),
            DesiredPathState::Entry { kind: RK::File, version: file_x }
        );
    }

    /// Deleting a directory deletes its explicit entry, not its subtree: a
    /// child still living keeps it on disk as a structural directory.
    #[test]
    fn desired_state_of_deleted_directory_with_live_child_is_not_absent() {
        let conn = conn();
        let dir = put_version(&conn, "g", b"", RK::Directory);
        let child = put_version(&conn, "g", b"child", RK::File);
        emit_local_change(&conn, "g", vec![put("photos", dir)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![put("photos/a.jpg", child)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![delete("photos")], &emitter()).unwrap();

        let hash = desired_projected_path_state_hash(&conn, "g", "photos").unwrap();
        assert_ne!(
            hash,
            compute_resolved_path_state_hash("g", "photos", MaterializedObjectKind::Absent, None)
        );
        assert_eq!(
            desired_path_state(&conn, "g", "photos").unwrap(),
            DesiredPathState::StructuralDirectory
        );

        // Once the last child is gone, nothing holds it any more.
        emit_local_change(&conn, "g", vec![delete("photos/a.jpg")], &emitter()).unwrap();
        assert_eq!(desired_path_state(&conn, "g", "photos").unwrap(), DesiredPathState::Absent);
    }

    #[test]
    fn an_explicit_directory_keeps_its_version_with_or_without_children() {
        let conn = conn();
        let dir = put_version(&conn, "g", b"", RK::Directory);
        emit_local_change(&conn, "g", vec![put("d", dir)], &emitter()).unwrap();
        assert_eq!(
            desired_path_state(&conn, "g", "d").unwrap(),
            DesiredPathState::ExplicitDirectory { version: dir }
        );
        let child = put_version(&conn, "g", b"child", RK::File);
        emit_local_change(&conn, "g", vec![put("d/c", child)], &emitter()).unwrap();
        assert_eq!(
            desired_path_state(&conn, "g", "d").unwrap(),
            DesiredPathState::ExplicitDirectory { version: dir }
        );
    }

    /// With no tree constraint, the namespace-aware state is the per-path
    /// one: the same hash the per-path builder gives.
    #[test]
    fn a_path_with_nothing_below_it_hashes_as_the_per_path_resolution_does() {
        let conn = conn();
        let file = put_version(&conn, "g", b"plain", RK::File);
        emit_local_change(&conn, "g", vec![put("a", file)], &emitter()).unwrap();
        // A sibling that shares the prefix is not below `a`.
        emit_local_change(&conn, "g", vec![put("a-b/x", file)], &emitter()).unwrap();
        let per_path = desired_resolved_path_state_hash(
            &conn,
            "g",
            "a",
            &PathResolution::Present { winner: 0, conflict_copies: vec![] },
            Some(&file),
        )
        .unwrap();
        assert_eq!(desired_projected_path_state_hash(&conn, "g", "a").unwrap(), per_path);
        assert_eq!(
            desired_projected_path_state_hash(&conn, "g", "never-written").unwrap(),
            compute_resolved_path_state_hash(
                "g",
                "never-written",
                MaterializedObjectKind::Absent,
                None
            )
        );
    }

    #[test]
    fn an_unresolvable_version_at_the_path_is_a_hard_error() {
        let conn = conn();
        // A version the change names but this replica does not hold.
        let missing = FileVersion::new(Vec::new(), 0, version_meta(RK::File)).version_hash;
        emit_local_change(&conn, "g", vec![put("a", missing)], &emitter()).unwrap();
        assert!(matches!(desired_path_state(&conn, "g", "a"), Err(SyncSqliteError::NotFound(_))));
    }

    /// A relocated entry is required at its copy name. The per-path read
    /// answers only a path's own account, so the copy name's state comes
    /// from the group's namespace projection, and every own-account answer
    /// agrees with it.
    #[test]
    fn a_relocated_file_is_required_at_its_copy_name() {
        let conn = conn();
        let file_a = put_version(&conn, "g", b"a as a file", RK::File);
        let file_x = put_version(&conn, "g", b"x below a", RK::File);
        let dir = put_version(&conn, "g", b"", RK::Directory);
        emit_local_change(&conn, "g", vec![put("a", file_a)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![put("a/x", file_x)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![put("d", dir)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![put("gone", file_x)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![delete("gone")], &emitter()).unwrap();

        let projection = desired_namespace_projection(&conn, "g").unwrap();
        let relocated: Vec<(&String, &PhysicalNode)> = projection
            .nodes()
            .iter()
            .filter(|(_, node)| {
                matches!(node, PhysicalNode::Entry(e) if e.placement == Placement::Relocated)
            })
            .collect();
        assert_eq!(relocated.len(), 1, "{:?}", projection.nodes());
        let (copy_name, node) = relocated[0];
        assert_ne!(copy_name, "a");
        let state = DesiredPathState::of_node(Some(node));
        assert_eq!(state, DesiredPathState::Entry { kind: RK::File, version: file_a });
        assert_eq!(
            state.resolved_path_state_hash("g", copy_name),
            compute_resolved_path_state_hash(
                "g",
                copy_name,
                MaterializedObjectKind::RegularFile,
                Some(&file_a)
            )
        );

        for (path, node) in projection.nodes() {
            if matches!(node, PhysicalNode::Entry(e) if e.placement != Placement::AtPath) {
                continue;
            }
            assert_eq!(
                desired_path_state(&conn, "g", path).unwrap(),
                DesiredPathState::of_node(Some(node)),
                "{path}"
            );
        }
        assert!(projection.get("gone").is_none());
    }

    /// A level read from its own subtree places the same nodes the whole
    /// projection does there: the relocated copy at the root, the file
    /// under a structural directory one level down, and nothing from a
    /// sibling whose name only shares a prefix.
    #[test]
    fn a_level_projection_equals_the_whole_projection_at_that_level() {
        let conn = conn();
        let file_a = put_version(&conn, "g", b"a as a file", RK::File);
        let file_x = put_version(&conn, "g", b"x below a", RK::File);
        emit_local_change(&conn, "g", vec![put("a", file_a)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![put("a/b/x", file_x)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![put("a-b", file_x)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![put("gone/y", file_x)], &emitter()).unwrap();
        emit_local_change(&conn, "g", vec![delete("gone/y")], &emitter()).unwrap();

        let whole = desired_namespace_projection(&conn, "g").unwrap();
        for parent in ["", "a", "a/b", "gone"] {
            let level = desired_level_projection(&conn, "g", parent).unwrap();
            let expected: Vec<(&String, &PhysicalNode)> = whole
                .nodes()
                .iter()
                .filter(|(path, _)| path.rsplit_once('/').map_or("", |(p, _)| p) == parent)
                .collect();
            let got: Vec<(&String, &PhysicalNode)> = level.nodes().iter().collect();
            assert_eq!(got, expected, "level {parent:?}");
        }
    }
}
