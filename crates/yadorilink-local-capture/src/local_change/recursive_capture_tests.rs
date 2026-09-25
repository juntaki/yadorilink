#![cfg(test)]

//! A recursive delete (`rm -rf d`) and a directory rename (`d -> e`) are
//! captured as one signed recursive operation: the point ops on the
//! explicit entries this device observed, cut into parts that each carry
//! the operation's descriptor. The set is observed-remove: an entry this
//! device never had on disk is not in it. A rename moves explicit entries
//! only; a structural directory stays structural under its new name.

use std::collections::{BTreeMap, BTreeSet};

use super::directory_capture::{
    event, index_in_flight_remote_entry, live_kind, ops_at, record_structural, GROUP,
};
use super::*;
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::recursive_operation::{
    EffectSetHash, RecursiveOperationKind, RecursiveOperationRef,
};
use yadorilink_sync_sqlite::dag_store::RecursiveOperationCompleteness;

/// The part size capture cuts a recursive operation into.
const PART_OP_LIMIT: usize = 256;

fn changes(state: &TestReplica) -> Vec<Change> {
    state.change_history_repository().dag_list_group_changes(GROUP).unwrap()
}

/// Every change carrying a recursive-operation part, in part order.
fn parts(state: &TestReplica) -> Vec<Change> {
    let mut parts: Vec<Change> =
        changes(state).into_iter().filter(|c| c.recursive_operation.is_some()).collect();
    parts.sort_by_key(|c| c.recursive_operation.as_ref().unwrap().part_index);
    parts
}

/// The paths each op kind of `parts` acts on: `delete` and `put`.
fn effect_paths(parts: &[Change]) -> BTreeMap<&'static str, BTreeSet<String>> {
    let mut out: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    for part in parts {
        for op in &part.ops {
            match op {
                Op::Delete { path } => {
                    assert!(
                        out.entry("delete").or_default().insert(path.as_str().to_string()),
                        "{path:?} deleted twice"
                    );
                }
                Op::Put { path, .. } => {
                    assert!(
                        out.entry("put").or_default().insert(path.as_str().to_string()),
                        "{path:?} put twice"
                    );
                }
                Op::Move { .. } => panic!("a recursive operation is authored as deletes and puts"),
            }
        }
    }
    out
}

fn set(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|p| p.to_string()).collect()
}

/// Asserts `parts` are all the parts of one operation of `kind`, complete
/// here, and returns its reference.
fn assert_one_complete_operation(
    state: &TestReplica,
    parts: &[Change],
    kind: RecursiveOperationKind,
) -> RecursiveOperationRef {
    assert!(!parts.is_empty(), "no recursive-operation part was authored");
    let first = parts[0].recursive_operation.clone().unwrap();
    assert_eq!(first.kind, kind);
    assert_eq!(first.part_count as usize, parts.len(), "every part is here");
    for (index, part) in parts.iter().enumerate() {
        let descriptor = part.recursive_operation.as_ref().unwrap();
        assert_eq!(descriptor.part_index as usize, index);
        assert_eq!(descriptor.descriptor(), first.descriptor(), "parts disagree");
    }
    let all_ops: Vec<Op> = parts.iter().flat_map(|p| p.ops.iter().cloned()).collect();
    assert_eq!(EffectSetHash::of_effects(&all_ops), first.effect_set_hash);
    let operation = RecursiveOperationRef {
        author: parts[0].device_id.clone(),
        operation_id: first.operation_id,
    };
    let recorded = state.sqlite().dag_recursive_operation(GROUP, &operation).unwrap().unwrap();
    assert_eq!(recorded.completeness(), RecursiveOperationCompleteness::Complete);
    operation
}

async fn flush(proc: &LocalChangeProcessor, root: &Path, paths: &[(&str, FsChangeKind)]) {
    proc.process_flush(
        GROUP,
        root,
        DebounceFlush::Paths(paths.iter().map(|(rel, kind)| (root.join(rel), *kind, 1)).collect()),
    )
    .await
    .unwrap();
}

/// `rm -rf d` over more entries than one part carries: one point delete
/// per observed explicit entry, `d` included, cut into ceil(n / limit)
/// parts of one operation.
#[test]
fn rm_rf_emits_point_deletes_for_observed_set_in_ceil_chunks() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("d/sub")).unwrap();
    let mut expected = vec!["d".to_string(), "d/sub".to_string()];
    for i in 0..300 {
        let rel = format!("d/f{i:03}.txt");
        std::fs::write(root.join(&rel), rel.as_bytes()).unwrap();
        expected.push(rel);
    }
    proc.scan_existing_files(GROUP, &root).unwrap();
    assert!(parts(&state).is_empty());

    std::fs::remove_dir_all(root.join("d")).unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(event(
        &proc,
        &root,
        &root.join("d"),
        FsChangeKind::Removed,
    ));

    let parts = parts(&state);
    assert_eq!(parts.len(), expected.len().div_ceil(PART_OP_LIMIT));
    assert!(parts.iter().all(|p| p.ops.len() <= PART_OP_LIMIT));
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("d".into()) },
    );
    let effects = effect_paths(&parts);
    assert_eq!(effects.get("delete"), Some(&expected.iter().cloned().collect()));
    assert_eq!(effects.get("put"), None);
    // No delete of the tree was authored outside the operation.
    for change in changes(&state) {
        if change.recursive_operation.is_none() {
            assert!(!change.ops.iter().any(|op| matches!(op, Op::Delete { .. })));
        }
    }
    for rel in &expected {
        assert_eq!(live_kind(&state, rel), None, "{rel} is still live");
    }
}

/// Every entry in the tree was authored by a change of its own; the
/// operation's parts consume every one of them, so nothing but the parts
/// is left a head.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rm_rf_multi_op_change_parents_cover_every_touched_basis() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("d/e")).unwrap();
    for rel in ["d/a", "d/b", "d/e/c"] {
        std::fs::write(root.join(rel), rel.as_bytes()).unwrap();
    }
    std::fs::write(root.join("outside"), b"o").unwrap();
    for rel in ["d", "d/e", "d/a", "d/b", "d/e/c", "outside"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("d")).unwrap();
    event(&proc, &root, &root.join("d"), FsChangeKind::Removed).await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("d".into()) },
    );
    let part_hashes: BTreeSet<_> = parts.iter().map(|p| p.compute_hash()).collect();
    let heads: BTreeSet<_> = state.sqlite().dag_group_heads(GROUP).unwrap().into_iter().collect();
    for change in changes(&state) {
        let touches_tree = change.ops.iter().any(|op| match op {
            Op::Put { path, .. } | Op::Delete { path } => {
                path.as_str() == "d" || path.as_str().starts_with("d/")
            }
            Op::Move { .. } => true,
        });
        let hash = change.compute_hash();
        if touches_tree && !part_hashes.contains(&hash) {
            assert!(
                !heads.contains(&hash),
                "a version the delete observed is still a head beside it: {change:?}"
            );
        }
    }
}

/// The children's own `Removed` events and their directory's arrive in one
/// flush: the whole tree is still one operation, so a folder restore gets
/// all of it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_and_its_children_removed_in_one_flush_are_one_operation() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("a")).unwrap();
    std::fs::write(root.join("a/x"), b"x").unwrap();
    std::fs::write(root.join("a/y"), b"y").unwrap();
    for rel in ["a", "a/x", "a/y"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("a")).unwrap();
    flush(
        &proc,
        &root,
        &[
            ("a/x", FsChangeKind::Removed),
            ("a/y", FsChangeKind::Removed),
            ("a", FsChangeKind::Removed),
        ],
    )
    .await;

    let parts = parts(&state);
    let operation = assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("a".into()) },
    );
    assert_eq!(effect_paths(&parts).get("delete"), Some(&set(&["a", "a/x", "a/y"])));
    assert_eq!(ops_at(&state, "a/x"), ["put-file", "delete"]);
    // The trashed versions carry the operation, which is what a folder
    // restore reads once the deleting changes are compacted away.
    let trashed: BTreeSet<String> = state
        .file_index_repository()
        .list_trashed_by_recursive_operation(GROUP, &operation)
        .unwrap()
        .into_iter()
        .map(|t| t.path)
        .collect();
    assert_eq!(trashed, set(&["a", "a/x", "a/y"]));
}

/// `mv d e` of an explicit directory: one rename operation deleting each
/// observed entry under `d` and putting it under `e`, with the same
/// content.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_of_explicit_directory_is_one_recursive_rename_operation() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("d/sub")).unwrap();
    std::fs::write(root.join("d/f.txt"), b"moved").unwrap();
    for rel in ["d", "d/sub", "d/f.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::rename(root.join("d"), root.join("e")).unwrap();
    flush(&proc, &root, &[("d", FsChangeKind::Removed), ("e", FsChangeKind::CreatedOrModified)])
        .await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RenameTree { from: SyncPath("d".into()), to: SyncPath("e".into()) },
    );
    let effects = effect_paths(&parts);
    assert_eq!(effects.get("delete"), Some(&set(&["d", "d/sub", "d/f.txt"])));
    assert_eq!(effects.get("put"), Some(&set(&["e", "e/sub", "e/f.txt"])));
    assert_eq!(ops_at(&state, "e"), ["put-dir"]);
    assert_eq!(ops_at(&state, "e/sub"), ["put-dir"]);
    assert_eq!(ops_at(&state, "e/f.txt"), ["put-file"]);
    let moved = state.file_index_repository().get_file(GROUP, "e/f.txt").unwrap().unwrap();
    assert!(!moved.deleted);
    assert_eq!(moved.size, 5);
    assert_eq!(live_kind(&state, "d/f.txt"), None);
}

/// FSEvents reports both sides of a rename as a change of unknown
/// direction, and in no particular order. What is on disk pairs them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_reported_without_sides_is_still_one_rename() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("d")).unwrap();
    std::fs::write(root.join("d/f.txt"), b"moved").unwrap();
    for rel in ["d", "d/f.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::rename(root.join("d"), root.join("e")).unwrap();
    flush(
        &proc,
        &root,
        &[("e", FsChangeKind::CreatedOrModified), ("d", FsChangeKind::CreatedOrModified)],
    )
    .await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RenameTree { from: SyncPath("d".into()), to: SyncPath("e".into()) },
    );
    assert_eq!(effect_paths(&parts).get("put"), Some(&set(&["e", "e/f.txt"])));
}

/// A structural directory is renamed: it stays structural under its new
/// name. Only the explicit entries below it move; nothing is authored for
/// the directory at either name, then or on a later look.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_of_structural_directory_does_not_promote_destination() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("s")).unwrap();
    record_structural(&state, &root, "s");
    std::fs::write(root.join("s/f.txt"), b"f").unwrap();
    event(&proc, &root, &root.join("s/f.txt"), FsChangeKind::CreatedOrModified).await;

    std::fs::rename(root.join("s"), root.join("t")).unwrap();
    flush(&proc, &root, &[("s", FsChangeKind::Removed), ("t", FsChangeKind::CreatedOrModified)])
        .await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RenameTree { from: SyncPath("s".into()), to: SyncPath("t".into()) },
    );
    let effects = effect_paths(&parts);
    assert_eq!(effects.get("delete"), Some(&set(&["s/f.txt"])));
    assert_eq!(effects.get("put"), Some(&set(&["t/f.txt"])));

    event(&proc, &root, &root.join("t"), FsChangeKind::CreatedOrModified).await;
    proc.scan_existing_files(GROUP, &root).unwrap();
    assert_eq!(ops_at(&state, "t"), Vec::<String>::new(), "the renamed container was promoted");
    assert_eq!(ops_at(&state, "s"), Vec::<String>::new());
    assert_eq!(live_kind(&state, "t"), None);
}

/// A rename moves the entries this device observed. A peer's entry
/// indexed under the old name but not yet on disk here was not moved by
/// the user, and stays in the old namespace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_directory_vs_concurrent_child_keeps_child_in_old_namespace() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    index_in_flight_remote_entry(&state, "d/new.txt");
    std::fs::create_dir(root.join("d")).unwrap();
    std::fs::write(root.join("d/f.txt"), b"moved").unwrap();
    for rel in ["d", "d/f.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::rename(root.join("d"), root.join("e")).unwrap();
    flush(&proc, &root, &[("d", FsChangeKind::Removed), ("e", FsChangeKind::CreatedOrModified)])
        .await;

    let effects = effect_paths(&parts(&state));
    assert_eq!(effects.get("delete"), Some(&set(&["d", "d/f.txt"])));
    assert_eq!(effects.get("put"), Some(&set(&["e", "e/f.txt"])));
    assert!(state
        .file_index_repository()
        .get_file(GROUP, "d/new.txt")
        .unwrap()
        .is_some_and(|r| !r.deleted));
    assert_eq!(ops_at(&state, "d/new.txt"), Vec::<String>::new());
    assert!(state.file_index_repository().get_file(GROUP, "e/new.txt").unwrap().is_none());
}

/// `rm a; mkdir a`: the file entry is replaced by a directory entry, not
/// left live beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_replaced_by_a_directory_retires_the_file_entry() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::write(root.join("a"), b"file").unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::CreatedOrModified).await;

    std::fs::remove_file(root.join("a")).unwrap();
    std::fs::create_dir(root.join("a")).unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "a"), ["put-file", "put-dir"]);
    assert_eq!(live_kind(&state, "a"), Some(RecordKind::Directory));
}

/// `rm -rf d; echo > d` coalesced into one event for `d`: the entries
/// observed under the directory are deleted, and `d` becomes the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_replaced_by_a_file_deletes_its_observed_descendants() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("d")).unwrap();
    std::fs::write(root.join("d/x"), b"x").unwrap();
    for rel in ["d", "d/x"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("d")).unwrap();
    std::fs::write(root.join("d"), b"now a file").unwrap();
    event(&proc, &root, &root.join("d"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "d/x"), ["put-file", "delete"]);
    assert_eq!(ops_at(&state, "d"), ["put-dir", "put-file"]);
    assert_eq!(live_kind(&state, "d"), Some(RecordKind::File));
    assert_eq!(live_kind(&state, "d/x"), None);
}

/// Finder deleting a folder through File Provider, or Explorer through the
/// cloud-files API, reaches capture as a single removal of the folder
/// (the virtual filesystem's delete callback routes to this same event
/// path). A structural folder has no entry of its own: its removal is the
/// point deletes of the entries observed in it, never a delete of a path
/// that holds no entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_virtual_filesystem_delete_of_a_structural_folder_expands_to_point_deletes() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("s")).unwrap();
    record_structural(&state, &root, "s");
    std::fs::write(root.join("s/x"), b"x").unwrap();
    std::fs::write(root.join("s/y"), b"y").unwrap();
    for rel in ["s/x", "s/y"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("s")).unwrap();
    event(&proc, &root, &root.join("s"), FsChangeKind::Removed).await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("s".into()) },
    );
    assert_eq!(effect_paths(&parts).get("delete"), Some(&set(&["s/x", "s/y"])));
    assert_eq!(ops_at(&state, "s"), Vec::<String>::new(), "a delete of a path with no entry");
}

/// A rename moves an entry to a name the user ignores: it is deleted at
/// its old name and not authored at the new one, exactly as the ordinary
/// capture of the new name would leave it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_does_not_author_an_entry_at_an_ignored_new_name() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("d")).unwrap();
    std::fs::write(root.join("d/kept.txt"), b"k").unwrap();
    std::fs::write(root.join("d/secret.txt"), b"s").unwrap();
    for rel in ["d", "d/kept.txt", "d/secret.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::write(root.join(".yadorilinkignore"), b"e/secret.txt\n").unwrap();
    std::fs::rename(root.join("d"), root.join("e")).unwrap();
    flush(&proc, &root, &[("d", FsChangeKind::Removed), ("e", FsChangeKind::CreatedOrModified)])
        .await;

    let effects = effect_paths(&parts(&state));
    assert_eq!(effects.get("delete"), Some(&set(&["d", "d/kept.txt", "d/secret.txt"])));
    assert_eq!(effects.get("put"), Some(&set(&["e", "e/kept.txt"])));
    assert!(state.file_index_repository().get_file(GROUP, "e/secret.txt").unwrap().is_none());
}

/// `rm -rf a` over more entries than one debounce flush holds: the
/// watcher flushes the children's removals before `a`'s own (it flushes
/// early on a burst, and at least every couple of seconds), and `rm`
/// removes the children first. A child removed while its directory is
/// already gone is still part of the directory's removal, so the whole
/// tree is one operation and a folder restore gets all of it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_rm_rf_split_across_flushes_is_still_one_operation() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("a/sub")).unwrap();
    for rel in ["a/x", "a/y", "a/sub/z"] {
        std::fs::write(root.join(rel), rel.as_bytes()).unwrap();
    }
    for rel in ["a", "a/sub", "a/x", "a/y", "a/sub/z"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("a")).unwrap();
    flush(&proc, &root, &[("a/x", FsChangeKind::Removed), ("a/sub/z", FsChangeKind::Removed)])
        .await;
    flush(
        &proc,
        &root,
        &[
            ("a/y", FsChangeKind::Removed),
            ("a/sub", FsChangeKind::Removed),
            ("a", FsChangeKind::Removed),
        ],
    )
    .await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("a".into()) },
    );
    assert_eq!(
        effect_paths(&parts).get("delete"),
        Some(&set(&["a", "a/sub", "a/x", "a/y", "a/sub/z"]))
    );
    for change in changes(&state) {
        if change.recursive_operation.is_none() {
            assert!(
                !change.ops.iter().any(|op| matches!(op, Op::Delete { .. })),
                "a delete of the tree was authored outside the operation: {change:?}"
            );
        }
    }
}

/// A folder deleted while the daemon was stopped is found by the full
/// scan. It is still one recursive operation (explicit or structural
/// folder alike), so it can be restored as the unit it was removed as; a
/// loose file deleted beside it stays an ordinary delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_folder_delete_is_one_recursive_operation() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("a/sub")).unwrap();
    std::fs::create_dir(root.join("s")).unwrap();
    record_structural(&state, &root, "s");
    for rel in ["a/x", "a/sub/y", "s/z", "loose"] {
        std::fs::write(root.join(rel), rel.as_bytes()).unwrap();
    }
    for rel in ["a", "a/sub", "a/x", "a/sub/y", "s/z", "loose"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("a")).unwrap();
    std::fs::remove_dir_all(root.join("s")).unwrap();
    std::fs::remove_file(root.join("loose")).unwrap();
    proc.scan_existing_files(GROUP, &root).unwrap();

    let parts = parts(&state);
    let mut by_operation: BTreeMap<[u8; 16], Vec<Change>> = BTreeMap::new();
    for part in parts {
        by_operation
            .entry(part.recursive_operation.as_ref().unwrap().operation_id.0)
            .or_default()
            .push(part);
    }
    let mut roots = BTreeMap::new();
    for operation in by_operation.values() {
        let kind = operation[0].recursive_operation.as_ref().unwrap().kind.clone();
        assert_one_complete_operation(&state, operation, kind.clone());
        let RecursiveOperationKind::RmTree { root } = kind else { panic!("{kind:?}") };
        roots.insert(root.as_str().to_string(), effect_paths(operation).get("delete").cloned());
    }
    assert_eq!(
        roots,
        BTreeMap::from([
            ("a".to_string(), Some(set(&["a", "a/sub", "a/x", "a/sub/y"]))),
            ("s".to_string(), Some(set(&["s/z"]))),
        ])
    );
    assert_eq!(ops_at(&state, "loose"), ["put-file", "delete"]);
    assert_eq!(live_kind(&state, "a/sub/y"), None);
    assert_eq!(live_kind(&state, "s/z"), None);
}

/// A rename writes its new paths, `to` itself included, so it takes their
/// locks: a writer holding `to`'s lock (a remote apply, a `chmod` capture)
/// finishes before the rename reads and writes `to`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_rename_waits_for_the_destination_lock() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("a")).unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::CreatedOrModified).await;

    std::fs::rename(root.join("a"), root.join("b")).unwrap();
    let held = state.path_lock_registry().path_lock(GROUP, "b").lock_owned().await;
    let blocked = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        flush(
            &proc,
            &root,
            &[("a", FsChangeKind::Removed), ("b", FsChangeKind::CreatedOrModified)],
        ),
    )
    .await;
    assert!(blocked.is_err(), "the rename wrote `b` without its lock");
    assert_eq!(ops_at(&state, "b"), Vec::<String>::new());

    drop(held);
    flush(&proc, &root, &[("a", FsChangeKind::Removed), ("b", FsChangeKind::CreatedOrModified)])
        .await;
    assert_eq!(effect_paths(&parts(&state)).get("put"), Some(&set(&["b"])));
}

/// Every path lock is taken in one canonical order. A rename `zeta ->
/// alpha` must not hold `zeta` while waiting on `alpha/x`: a batch that
/// holds `alpha/x` and then takes `zeta` (sorted, as every batch locks)
/// would wait on it forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_rename_takes_its_locks_in_canonical_order() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("zeta")).unwrap();
    std::fs::write(root.join("zeta/x"), b"x").unwrap();
    for rel in ["zeta", "zeta/x"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }
    std::fs::rename(root.join("zeta"), root.join("alpha")).unwrap();

    // A batch writer over `alpha/x` and `zeta`, in sorted order.
    let registry = state.path_lock_registry();
    let first = registry.path_lock(GROUP, "alpha/x").lock_owned().await;
    let second = registry.path_lock(GROUP, "zeta");
    let batch = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _second = second.lock_owned().await;
        drop(first);
    });

    let captured = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        flush(
            &proc,
            &root,
            &[("zeta", FsChangeKind::Removed), ("alpha", FsChangeKind::CreatedOrModified)],
        ),
    )
    .await;
    assert!(captured.is_ok(), "the rename and a sorted batch deadlocked");
    tokio::time::timeout(std::time::Duration::from_secs(10), batch).await.unwrap().unwrap();
    assert_eq!(effect_paths(&parts(&state)).get("put"), Some(&set(&["alpha", "alpha/x"])));
}

/// A directory made where a peer's file is indexed but held off disk here
/// (a name hazard) does not replace that file's entry: the file was never
/// on disk, so nobody replaced it. The same vetoes decide this as decide
/// which entries a vanished directory held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_over_a_held_file_row_does_not_replace_it() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "a".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(GROUP, "a", MaterializationState::Placeholder, &permit)
        .unwrap();
    state.materialization_state_repository().set_held(GROUP, "a", "case_collision", 0).unwrap();

    std::fs::create_dir(root.join("a")).unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "a"), Vec::<String>::new());
    assert_eq!(live_kind(&state, "a"), Some(RecordKind::File));
}
