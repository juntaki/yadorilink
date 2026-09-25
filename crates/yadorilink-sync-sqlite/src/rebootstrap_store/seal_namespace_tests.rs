#![cfg(test)]
//! Sealing a group whose paths form a tree: `Gamma` holds every present
//! entry head (Directory heads included, structural directories never),
//! and the rows a seal carries are the namespace projection of `Gamma`,
//! not the per-path winners. A file displaced by a descendant or by a
//! directory at its own path is carried at the copy name the projection
//! gives it, and a joiner that installs the base places it there as a
//! projection of the displaced path's head, never as a path of its own.

use super::base_install_tests::open;
use super::seal_tests::{admit, delete, put, refusal, seal, store_versions, version, GROUP};
use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, canonical_signing_bytes, checkpoint_hash, encode_merkle_proof, merkle_root,
    sign_checkpoint, AuthorizationCheckpoint,
};
use yadorilink_replica_domain::file::{FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::session_state::LocalFileMetaColumns;
use yadorilink_replica_domain::test_authoring::reset_author_sequences;
use yadorilink_replica_engine::conflict::PathHead;
use yadorilink_replica_engine::namespace::{
    project, DirectoryNode, NamespaceProjection, PhysicalNode, Placement,
};

pub(super) fn directory(mode: u32) -> FileVersion {
    FileVersion::directory(Some(mode))
}

pub(super) fn store_directories(conn: &Connection) {
    for mode in [0o700, 0o755] {
        crate::dag_store::put_file_version(conn, GROUP, &directory(mode)).unwrap();
    }
}

/// Publishes every retained change under one genuine authorization
/// checkpoint, each with its own inclusion proof, so a row a pruned change
/// wrote carries evidence a joiner can install.
pub(super) fn publish(conn: &Connection) {
    let leaves: Vec<[u8; 32]> = {
        let mut stmt = conn
            .prepare(
                "SELECT c.change_hash FROM changes c WHERE c.group_id = ?1 AND NOT EXISTS \
                 (SELECT 1 FROM change_authorization ca WHERE ca.change_hash = c.change_hash) \
                 ORDER BY c.change_hash",
            )
            .unwrap();
        let rows = stmt.query_map([GROUP], |row| row.get::<_, Vec<u8>>(0)).unwrap();
        rows.map(|row| row.unwrap().try_into().unwrap()).collect()
    };
    let checkpoint = AuthorizationCheckpoint {
        group_id: GROUP.to_string(),
        device_id: "device-a".to_string(),
        signing_key_fingerprint: [1; 32],
        merkle_root: merkle_root(&leaves),
        leaf_count: leaves.len() as u64,
        checkpoint_seq: 1,
        signer_key_id: [2; 32],
        policy_epoch: 1,
        policy_seq: 1,
        policy_head: [3; 32],
        issued_at_unix: 0,
    };
    let encoded = canonical_signing_bytes(&checkpoint);
    let signature = sign_checkpoint(&checkpoint, &SigningKey::from_bytes(&[42; 32]));
    let entries: Vec<(ChangeHash, Vec<u8>)> = leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            (ChangeHash(*leaf), encode_merkle_proof(&build_merkle_proof(&leaves, index)))
        })
        .collect();
    crate::dag_store::published_view::attach_authorization_evidence(
        conn,
        &checkpoint_hash(&encoded, &signature),
        GROUP,
        "device-a",
        1,
        &encoded,
        &signature,
        &[7; 32],
        &entries,
    )
    .unwrap();
}

pub(super) fn kind_of(conn: &Connection) -> impl Fn(&[u8; 32]) -> Option<RecordKind> + '_ {
    move |hash| {
        crate::dag_store::get_file_version(conn, GROUP, &VersionHash(*hash))
            .unwrap()
            .map(|version| version.meta.record_kind)
    }
}

/// The group's live heads projected onto a tree.
pub(super) fn live_projection(conn: &Connection) -> NamespaceProjection {
    let heads = crate::dag_store::path_frontier::live_heads_by_path(conn, GROUP).unwrap();
    project(&heads, kind_of(conn)).unwrap()
}

pub(super) fn current_row(conn: &Connection, path: &str) -> Option<(VersionHash, bool)> {
    let deleted: Option<bool> = conn
        .query_row(
            "SELECT deleted FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
            [GROUP, path],
            |row| row.get::<_, i64>(0).map(|d| d != 0),
        )
        .optional()
        .unwrap();
    let row = crate::store::read_canonical_current_row(conn, GROUP, path).unwrap()?;
    Some((row.version_hash(), deleted.unwrap_or(false)))
}

fn write_row(
    tx: &rusqlite::Transaction<'_>,
    path: &str,
    version: &FileVersion,
    author: &[u8; 32],
    origin: &str,
    deleted: bool,
) {
    crate::file_index::upsert_file_in_tx(
        tx,
        GROUP,
        &FileRecord {
            path: path.to_string(),
            size: version.size,
            mtime_unix_nanos: version.meta.mtime_unix_nanos,
            blocks: Vec::new(),
            deleted,
        },
        origin,
        Some(&ChangeHash(*author)),
    )
    .unwrap();
    crate::file_index::apply_local_meta_columns_in_tx(
        tx,
        GROUP,
        path,
        &LocalFileMetaColumns {
            record_kind: version.meta.record_kind,
            symlink_target: version.meta.symlink_target.clone(),
            symlink_out_of_root: false,
            unix_mode: version.meta.unix_mode,
            xattrs: Vec::new(),
        },
    )
    .unwrap();
}

/// Erases every row at `path`, as the sealing device's reconcile pass
/// displaces a leaf a directory needs (`displace_leaf_for_directory` ->
/// `settle_retired_copy_erase` -> `erase_local_only_file`): the leaf's
/// history at `path` is removed, not superseded, and its content is
/// written afresh at its copy name, on top of that name's own history.
/// (A joiner's install relocates differently -- `move_current_rows`
/// supersedes -- but only for rows the sealer would not carry.)
fn erase_rows(tx: &rusqlite::Transaction<'_>, path: &str) {
    tx.execute("DELETE FROM files WHERE group_id = ?1 AND path = ?2", [GROUP, path]).unwrap();
}

/// The head of `path` that wrote `version`, best-ranked first.
fn writer_of<'a>(
    heads: &'a BTreeMap<String, Vec<PathHead>>,
    path: &str,
    version: &[u8; 32],
) -> &'a PathHead {
    heads[path]
        .iter()
        .filter(|head| head.content.as_ref().is_some_and(|c| c.version_hash == *version))
        .max_by_key(|head| (head.lamport, head.change_hash))
        .expect("a placed version has a head that wrote it")
}

/// Brings the file rows to the namespace projection of the live heads, as
/// the projection-driven reconcile pass leaves the index once it has
/// caught up: a relocated leaf's rows are erased at its path and its
/// content written at its copy name, an explicit
/// directory holds a Directory row, a structural directory holds none, and
/// a path the projection empties holds its removal's tombstone.
pub(super) fn project_tree(conn: &Connection) {
    let heads = crate::dag_store::path_frontier::live_heads_by_path(conn, GROUP).unwrap();
    let projection = project(&heads, kind_of(conn)).unwrap();
    let version = |hash: &[u8; 32]| {
        crate::dag_store::get_file_version(conn, GROUP, &VersionHash(*hash)).unwrap().unwrap()
    };
    let tx = conn.unchecked_transaction().unwrap();
    for (name, node) in projection.nodes() {
        if let PhysicalNode::Entry(entry) = node {
            if entry.placement == Placement::Relocated
                && current_row(&tx, &entry.source) == Some((VersionHash(entry.version_hash), false))
            {
                erase_rows(&tx, &entry.source);
            }
        }
    }
    for (name, node) in projection.nodes() {
        let (source, version_hash) = match node {
            PhysicalNode::Entry(entry) => (entry.source.as_str(), entry.version_hash),
            PhysicalNode::Directory(DirectoryNode::Explicit { version_hash }) => {
                (name.as_str(), *version_hash)
            }
            PhysicalNode::Directory(DirectoryNode::Structural) => continue,
        };
        if current_row(&tx, name) == Some((VersionHash(version_hash), false)) {
            continue;
        }
        let head = writer_of(&heads, source, &version_hash);
        write_row(&tx, name, &version(&version_hash), &head.change_hash, &head.device_id, false);
    }
    for (path, path_heads) in &heads {
        let placed_here = matches!(
            projection.get(path),
            Some(PhysicalNode::Entry(_) | PhysicalNode::Directory(DirectoryNode::Explicit { .. }))
        );
        let Some(removal) = path_heads.iter().find(|head| head.content.is_none()) else {
            continue;
        };
        if placed_here {
            continue;
        }
        if let Some((row_version, false)) = current_row(&tx, path) {
            let removed = version(&row_version.0);
            write_row(&tx, path, &removed, &removal.change_hash, &removal.device_id, true);
        }
    }
    tx.execute("DELETE FROM projection_obligations WHERE group_id = ?1", [GROUP]).unwrap();
    tx.commit().unwrap();
}

fn live_snapshot_rows(snapshot: &RebootstrapSnapshot) -> BTreeMap<String, VersionHash> {
    snapshot
        .files
        .iter()
        .filter(|file| file.state == SnapshotVersionState::Current && !file.record.deleted)
        .map(|file| {
            let version = FileVersion::from_index_row(
                file.record.blocks.clone(),
                file.record.size,
                file.record.mtime_unix_nanos,
                file.record_kind,
                file.unix_mode,
                file.symlink_target.clone(),
                file.xattrs.clone(),
            );
            (file.record.path.clone(), version.version_hash)
        })
        .collect()
}

pub(super) fn live_rows(conn: &Connection) -> BTreeMap<String, VersionHash> {
    let paths: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT path FROM files \
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0 ORDER BY path",
            )
            .unwrap();
        let rows = stmt.query_map([GROUP], |row| row.get::<_, String>(0)).unwrap();
        rows.map(Result::unwrap).collect()
    };
    paths
        .into_iter()
        .map(|path| {
            let (version, _) = current_row(conn, &path).unwrap();
            (path, version)
        })
        .collect()
}

/// Installs `sealed` into a fresh replica, as a joiner would.
fn install_on_joiner(sealed: &VerifiedSeal) -> Connection {
    let mut joiner = open();
    let tx = joiner.transaction().unwrap();
    install_base_for_tests(&tx, sealed.checkpoint(), sealed.snapshot()).unwrap();
    tx.commit().unwrap();
    joiner
}

/// The node the projection of an installed base's summary places at
/// `name`, computed on the joiner from what it installed.
fn installed_projection(joiner: &Connection) -> NamespaceProjection {
    history_base_summary(joiner, GROUP).unwrap().unwrap().project(kind_of(joiner)).unwrap()
}

fn the_relocation(projection: &NamespaceProjection, source: &str) -> (String, [u8; 32]) {
    let mut relocated = projection.nodes().iter().filter_map(|(name, node)| match node {
        PhysicalNode::Entry(entry)
            if entry.placement == Placement::Relocated && entry.source == source =>
        {
            Some((name.clone(), entry.version_hash))
        }
        _ => None,
    });
    let found = relocated.next().expect("a relocated entry");
    assert!(relocated.next().is_none(), "one relocation of {source}");
    found
}

/// `A` writes a file `a` while `B` concurrently writes `a/x`. The
/// projection makes `a` a structural directory and relocates the file to
/// its copy name, and that is what the index holds: no row at `a`, the
/// file's row at the copy name. The seal counts the copy-name row as the
/// materialization of `a`'s head, and carries it where the index holds it
/// -- with `Gamma` naming `a` and nothing at the copy name, so a joiner
/// installs the copy-name row as a projection of `a`, not as a path of
/// its own, and does not relocate it a second time.
#[test]
fn seal_accepts_projected_rows_for_file_vs_descendant_conflict() {
    let conn = open();
    reset_author_sequences();
    store_versions(&conn);
    let a = admit(&conn, "device-a", &[], vec![put("a", &version(1))]);
    let x = admit(&conn, "device-b", &[], vec![put("a/x", &version(2))]);
    publish(&conn);
    project_tree(&conn);
    let (copy_name, relocated) = the_relocation(&live_projection(&conn), "a");
    assert_eq!(relocated, version(1).version_hash.0);
    assert_eq!(current_row(&conn, "a"), None, "the displacement erased a's rows");

    let sealed = seal(&conn);

    let carried = live_snapshot_rows(sealed.snapshot());
    assert_eq!(
        carried,
        BTreeMap::from([
            (copy_name.clone(), version(1).version_hash),
            ("a/x".to_string(), version(2).version_hash),
        ])
    );
    let heads: Vec<(String, ChangeHash)> = sealed
        .summary()
        .path_heads
        .iter()
        .map(|head| (head.path.clone(), head.change_hash))
        .collect();
    assert_eq!(
        heads,
        vec![("a".to_string(), a.compute_hash()), ("a/x".to_string(), x.compute_hash())],
        "Gamma names the path the file belongs to, never its copy name"
    );

    let joiner = install_on_joiner(&sealed);
    assert_eq!(live_rows(&joiner), carried, "installed exactly where the base carries it");
    assert_eq!(
        the_relocation(&installed_projection(&joiner), "a"),
        (copy_name, version(1).version_hash.0),
        "the joiner reads the copy-name row as a's relocated head"
    );
}

/// A directory at a path beats a file at the same path, even one that
/// ranks higher: the directory holds the path and the file sits at its
/// copy name. The per-path winner is the file, and the seal still accepts
/// the directory's row at the path.
#[test]
fn seal_accepts_directory_wins_over_file_at_same_path() {
    let conn = open();
    reset_author_sequences();
    store_versions(&conn);
    store_directories(&conn);
    let mkdir = admit(&conn, "device-a", &[], vec![put("a", &directory(0o755))]);
    // Only raises the file's Lamport; it writes nothing a row holds.
    let earlier = admit(&conn, "device-b", &[], vec![delete("z")]);
    let file = admit(&conn, "device-b", &[&earlier], vec![put("a", &version(1))]);
    assert!(file.lamport > mkdir.lamport, "the file ranks higher");
    publish(&conn);
    project_tree(&conn);
    let projection = live_projection(&conn);
    assert_eq!(
        projection.get("a"),
        Some(&PhysicalNode::Directory(DirectoryNode::Explicit {
            version_hash: directory(0o755).version_hash.0
        }))
    );
    let (copy_name, _) = the_relocation(&projection, "a");

    let sealed = seal(&conn);

    let carried = live_snapshot_rows(sealed.snapshot());
    assert_eq!(carried.get("a"), Some(&directory(0o755).version_hash));
    assert_eq!(carried.get(&copy_name), Some(&version(1).version_hash));
    let joiner = install_on_joiner(&sealed);
    assert_eq!(live_rows(&joiner), carried);
}

/// `mkdir a`, `a/x` written inside it, then `rmdir a` as a point delete:
/// `Gamma_a` is empty, but `a` is still a structural directory holding
/// `a/x`. Explicitly absent is not physically absent. The directory row
/// `a` had is a tombstone now; a seal may not carry a live one, because a
/// joiner would install it as an explicit directory nobody holds any more
/// and keep it after `a/x` goes.
#[test]
fn seal_after_explicit_dir_deleted_with_live_child_carries_no_dir_row() {
    let conn = open();
    reset_author_sequences();
    store_versions(&conn);
    store_directories(&conn);
    let mkdir = admit(&conn, "device-a", &[], vec![put("a", &directory(0o755))]);
    let child = admit(&conn, "device-a", &[&mkdir], vec![put("a/x", &version(2))]);
    let rmdir = admit(&conn, "device-a", &[&child], vec![delete("a")]);
    publish(&conn);
    project_tree(&conn);
    assert_eq!(
        live_projection(&conn).get("a"),
        Some(&PhysicalNode::Directory(DirectoryNode::Structural))
    );

    // A stale live directory row at the structural path is refused.
    {
        let tx = conn.unchecked_transaction().unwrap();
        write_row(&tx, "a", &directory(0o755), &mkdir.compute_hash().0, "device-a", false);
        tx.commit().unwrap();
    }
    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::RowAtStructuralDirectory { path: "a".to_string() }
    );

    {
        let tx = conn.unchecked_transaction().unwrap();
        write_row(&tx, "a", &directory(0o755), &rmdir.compute_hash().0, "device-a", true);
        tx.commit().unwrap();
    }
    let sealed = seal(&conn);

    assert!(!sealed.summary().path_heads.iter().any(|head| head.path == "a"));
    assert_eq!(
        live_snapshot_rows(sealed.snapshot()),
        BTreeMap::from([("a/x".to_string(), version(2).version_hash)])
    );
}

/// A current directory row where the projection has no directory at all
/// -- no head holds it and nothing lives below it -- is refused too: a
/// joiner would install it as an explicit directory.
#[test]
fn a_seal_refuses_a_directory_row_the_namespace_does_not_hold() {
    let conn = open();
    reset_author_sequences();
    store_versions(&conn);
    store_directories(&conn);
    let mkdir = admit(&conn, "device-a", &[], vec![put("d", &directory(0o755))]);
    admit(&conn, "device-a", &[&mkdir], vec![delete("d")]);
    publish(&conn);
    project_tree(&conn);
    {
        let tx = conn.unchecked_transaction().unwrap();
        write_row(&tx, "d", &directory(0o755), &mkdir.compute_hash().0, "device-a", false);
        tx.commit().unwrap();
    }

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::DirectoryWithoutHead { path: "d".to_string() }
    );
}

/// Two devices make the same directory with the same mode concurrently:
/// two writes of one version, and `Gamma` keeps both, exactly as it keeps
/// two identical file writes. One row materializes them.
#[test]
fn same_hash_directory_heads_are_not_collapsed_in_gamma() {
    let conn = open();
    reset_author_sequences();
    store_directories(&conn);
    let a = admit(&conn, "device-a", &[], vec![put("d", &directory(0o755))]);
    let b = admit(&conn, "device-b", &[], vec![put("d", &directory(0o755))]);
    publish(&conn);
    project_tree(&conn);

    let sealed = seal(&conn);

    let mut heads: Vec<ChangeHash> = sealed
        .summary()
        .path_heads
        .iter()
        .filter(|head| head.path == "d")
        .map(|head| head.change_hash)
        .collect();
    heads.sort();
    let mut expected = vec![a.compute_hash(), b.compute_hash()];
    expected.sort();
    assert_eq!(heads, expected);
    assert_eq!(
        live_snapshot_rows(sealed.snapshot()),
        BTreeMap::from([("d".to_string(), directory(0o755).version_hash)])
    );
}

/// `mkdir empty/` survives a seal and an install: `Gamma` carries its
/// Directory head, the base carries its Directory row, and a joiner that
/// installs the base holds the directory with its mode.
#[test]
fn sealed_empty_directory_round_trips_through_install() {
    let conn = open();
    reset_author_sequences();
    store_directories(&conn);
    let mkdir = admit(&conn, "device-a", &[], vec![put("empty", &directory(0o700))]);
    publish(&conn);
    project_tree(&conn);

    let sealed = seal(&conn);

    assert_eq!(
        sealed.summary().path_heads.iter().map(|head| head.change_hash).collect::<Vec<_>>(),
        vec![mkdir.compute_hash()]
    );
    let joiner = install_on_joiner(&sealed);
    assert_eq!(
        live_rows(&joiner),
        BTreeMap::from([("empty".to_string(), directory(0o700).version_hash)])
    );
    let kind: String = joiner
        .query_row(
            "SELECT record_kind FROM files WHERE group_id = ?1 AND path = 'empty' \
             AND state = 'current'",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(RecordKind::from_db_str(&kind), RecordKind::Directory);
    assert_eq!(
        installed_projection(&joiner).get("empty"),
        Some(&PhysicalNode::Directory(DirectoryNode::Explicit {
            version_hash: directory(0o700).version_hash.0
        }))
    );
}

/// A relocated file's copy name can have history of its own: a file once
/// written there and deleted. The relocated content's row continues that
/// history (the tombstone superseded, the new row after it) while `a`'s
/// own rows are erased, the seal carries the copy name's history, and the
/// joiner installs the new row as the copy name's current row, with the
/// old history kept as history (the removed file is still in the copy
/// name's trash, where its own removal put it).
#[test]
fn a_relocation_onto_a_copy_name_with_history_seals_and_installs() {
    let conn = open();
    reset_author_sequences();
    store_versions(&conn);
    let a = admit(&conn, "device-a", &[], vec![put("a", &version(1))]);
    admit(&conn, "device-b", &[], vec![put("a/x", &version(2))]);
    let heads = crate::dag_store::path_frontier::live_heads_by_path(&conn, GROUP).unwrap();
    let copy_name = yadorilink_replica_engine::namespace::first_copy_name(
        "a",
        writer_of(&heads, "a", &{ version(1).version_hash.0 }),
    );
    // Someone wrote a file under that very name and removed it again, all
    // before either write above was seen.
    let squatter = admit(&conn, "device-c", &[], vec![put(&copy_name, &version(5))]);
    let removed = admit(&conn, "device-c", &[&squatter], vec![delete(&copy_name)]);
    publish(&conn);
    {
        let tx = conn.unchecked_transaction().unwrap();
        write_row(&tx, "a", &version(1), &a.compute_hash().0, "device-a", false);
        write_row(&tx, &copy_name, &version(5), &squatter.compute_hash().0, "device-c", false);
        write_row(&tx, &copy_name, &version(5), &removed.compute_hash().0, "device-c", true);
        tx.commit().unwrap();
    }
    project_tree(&conn);
    assert_eq!(the_relocation(&live_projection(&conn), "a").0, copy_name);
    assert_eq!(current_row(&conn, &copy_name), Some((version(1).version_hash, false)));

    let rows_at_a: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM files WHERE group_id = ?1 AND path = 'a'",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(rows_at_a, 0, "the sealer erases a's history, it does not supersede it");

    let sealed = seal(&conn);
    assert!(
        !sealed.snapshot().files.iter().any(|file| file.record.path == "a"),
        "nothing of a's own history is carried"
    );

    let at_copy: Vec<(i64, SnapshotVersionState, bool)> = sealed
        .snapshot()
        .files
        .iter()
        .filter(|file| file.record.path == copy_name)
        .map(|file| (file.version_seq, file.state, file.record.deleted))
        .collect();
    assert_eq!(
        at_copy.last(),
        Some(&(at_copy.len() as i64, SnapshotVersionState::Current, false)),
        "the relocated content continues the copy name's history: {at_copy:?}"
    );
    assert!(
        at_copy[..at_copy.len() - 1]
            .iter()
            .all(|(_, state, _)| *state != SnapshotVersionState::Current),
        "the copy name's own history stays history: {at_copy:?}"
    );
    let joiner = install_on_joiner(&sealed);
    assert_eq!(
        live_rows(&joiner),
        BTreeMap::from([
            (copy_name, version(1).version_hash),
            ("a/x".to_string(), version(2).version_hash),
        ])
    );
}

/// A live row below a path the projection places as a leaf is refused,
/// even one the projection does not place at all (a local row that
/// outlived its heads): a joiner's install would relocate the leaf out
/// of the way of its "descendant", and its index would then disagree
/// with both the sealer's and its own projection of `Gamma`.
#[test]
fn a_seal_refuses_a_live_row_below_a_placed_file() {
    let conn = open();
    reset_author_sequences();
    store_versions(&conn);
    let child = admit(&conn, "device-b", &[], vec![put("a/y", &version(2))]);
    let gone = admit(&conn, "device-b", &[&child], vec![delete("a/y")]);
    admit(&conn, "device-a", &[&gone], vec![put("a", &version(1))]);
    publish(&conn);
    project_tree(&conn);
    assert!(matches!(
        live_projection(&conn).get("a"),
        Some(PhysicalNode::Entry(entry)) if entry.placement == Placement::AtPath
    ));
    {
        let tx = conn.unchecked_transaction().unwrap();
        write_row(&tx, "a/y", &version(2), &child.compute_hash().0, "device-b", false);
        tx.commit().unwrap();
    }

    assert_eq!(
        refusal(prepare_seal(&conn, GROUP)),
        SealRefusal::RowBelowLeaf { path: "a/y".to_string(), leaf: "a".to_string() }
    );
}

fn symlink(target: &str) -> FileVersion {
    FileVersion::new(
        Vec::new(),
        0,
        yadorilink_replica_domain::file::FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: Some(target.as_bytes().to_vec()),
            record_kind: RecordKind::Symlink,
            xattrs: Vec::new(),
        },
    )
}

/// DIR-1 at the seal: a File or Symlink and an explicit Directory at `a`,
/// in either rank order, with `a/x` or without. The seal carries the
/// Directory's row at `a` and the leaf's at its copy name, and a joiner
/// installs exactly that. A Directory row at a copy name -- the empty copy
/// the old tie-break gave a losing Directory -- is no head's, so a seal
/// that would carry one is refused.
#[test]
fn seal_keeps_the_directory_at_its_path_in_either_rank_order() {
    for leaf in [version(1), symlink("target")] {
        for leaf_ranks_higher in [true, false] {
            for with_descendant in [false, true] {
                let label = format!(
                    "{:?} ranks higher: {leaf_ranks_higher}, a/x: {with_descendant}",
                    leaf.meta.record_kind
                );
                let conn = open();
                reset_author_sequences();
                store_versions(&conn);
                store_directories(&conn);
                crate::dag_store::put_file_version(&conn, GROUP, &leaf).unwrap();
                // Only raises the higher side's Lamport; it writes no row.
                let (high_device, low_device) = if leaf_ranks_higher {
                    ("device-b", "device-a")
                } else {
                    ("device-a", "device-b")
                };
                let earlier = admit(&conn, high_device, &[], vec![delete("z")]);
                let (leaf_parents, dir_parents): (Vec<&Change>, Vec<&Change>) = if leaf_ranks_higher
                {
                    (vec![&earlier], vec![])
                } else {
                    (vec![], vec![&earlier])
                };
                let leaf_device = if leaf_ranks_higher { high_device } else { low_device };
                let dir_device = if leaf_ranks_higher { low_device } else { high_device };
                let mkdir =
                    admit(&conn, dir_device, &dir_parents, vec![put("a", &directory(0o755))]);
                let leaf_change = admit(&conn, leaf_device, &leaf_parents, vec![put("a", &leaf)]);
                assert_eq!(leaf_change.lamport > mkdir.lamport, leaf_ranks_higher, "{label}");
                if with_descendant {
                    admit(&conn, "device-c", &[], vec![put("a/x", &version(2))]);
                }
                publish(&conn);
                project_tree(&conn);
                let projection = live_projection(&conn);
                assert_eq!(
                    projection.get("a"),
                    Some(&PhysicalNode::Directory(DirectoryNode::Explicit {
                        version_hash: directory(0o755).version_hash.0
                    })),
                    "{label}"
                );
                let beside: Vec<(&String, &PhysicalNode)> = projection
                    .nodes()
                    .iter()
                    .filter(|(name, _)| name.as_str() != "a" && name.as_str() != "a/x")
                    .collect();
                assert_eq!(beside.len(), 1, "{label}: {beside:?}");
                let (copy_name, node) = beside[0];
                assert!(
                    matches!(node, PhysicalNode::Entry(entry)
                        if entry.version_hash == leaf.version_hash.0 && entry.source == "a"),
                    "{label}: {node:?}"
                );

                // The empty copy the old tie-break gave a losing Directory.
                let directory_copy =
                    yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
                        "a",
                        dir_device,
                        0,
                        &directory(0o755).version_hash.0,
                    );
                {
                    let tx = conn.unchecked_transaction().unwrap();
                    write_row(
                        &tx,
                        &directory_copy,
                        &directory(0o755),
                        &mkdir.compute_hash().0,
                        dir_device,
                        false,
                    );
                    tx.commit().unwrap();
                }
                assert_eq!(
                    refusal(prepare_seal(&conn, GROUP)),
                    SealRefusal::DirectoryWithoutHead { path: directory_copy.clone() },
                    "{label}"
                );
                {
                    let tx = conn.unchecked_transaction().unwrap();
                    erase_rows(&tx, &directory_copy);
                    tx.commit().unwrap();
                }

                let sealed = seal(&conn);

                let carried = live_snapshot_rows(sealed.snapshot());
                assert_eq!(carried.get("a"), Some(&directory(0o755).version_hash), "{label}");
                assert_eq!(carried.get(copy_name), Some(&leaf.version_hash), "{label}");
                assert_eq!(carried.len(), 2 + usize::from(with_descendant), "{label}");
                let joiner = install_on_joiner(&sealed);
                assert_eq!(live_rows(&joiner), carried, "{label}");
                let installed = installed_projection(&joiner);
                assert_eq!(installed.get("a"), projection.get("a"), "{label}");
                assert_eq!(installed.get(copy_name), Some(node), "{label}");
            }
        }
    }
}
