#![cfg(test)]
//! What the namespace makes reconcile do on disk is never captured as a
//! change of this device's own.
//!
//! When a peer's `a/x` arrives while this device holds its own File `a`,
//! reconcile moves the file beside the new directory under its
//! conflict-copy name. Capture then sees File `a` gone from its name and a
//! new file it never wrote. Were it to read that as the user's doing, it
//! would sign a Delete of `a` for every device (and a Put of the copy),
//! turning a local, derived arrangement into a replicated loss. Likewise a
//! directory this device keeps only as a container -- one it created, or
//! an explicit directory a peer deleted while a child still lives -- is
//! never authored back.

use super::growing_file_projection_tests::{Harness, GROUP, LOCAL_DEVICE};
use super::*;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::conflict::{conflict_copy_source_path, is_conflict_copy_path};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;
use yadorilink_sync_sqlite::structural_origin::StructuralOriginStatus;

fn remote_emitter() -> ChangeEmitter {
    ChangeEmitter::new("device-remote", SigningKey::from_bytes(&[9u8; 32]))
}

fn put(path: &str, version: VersionHash) -> Op {
    Op::Put { path: SyncPath(path.into()), version, origin: PutOrigin::Direct }
}

fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.into()) }
}

/// Emits a peer's change carrying `ops` on top of everything this device
/// holds, storing `versions` first.
fn remote_change(h: &Harness, ops: Vec<Op>, versions: &[FileVersion]) {
    let parents = h.state.dag_group_heads(GROUP).unwrap();
    let remote = remote_emitter();
    h.state
        .database()
        .write(|conn| {
            for version in versions {
                yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, version)?;
            }
            yadorilink_sync_sqlite::dag_store::emit_local_change_onto(
                conn,
                GROUP,
                parents.clone(),
                ops.clone(),
                &remote,
            )
        })
        .unwrap();
}

/// Stores `bytes` as a version whose blocks this device holds, by
/// capturing them under a scratch name.
async fn stored_version(h: &Harness, scratch: &str, bytes: &[u8]) -> VersionHash {
    std::fs::write(h.path(scratch), bytes).unwrap();
    assert!(matches!(h.capture(scratch).await, LocalChangeOutcome::FileChanged(_)));
    VersionHash(h.own_head(scratch).content.unwrap().version_hash)
}

fn own_change_count(h: &Harness) -> usize {
    h.state
        .change_history_repository()
        .dag_list_group_changes(GROUP)
        .unwrap()
        .iter()
        .filter(|change| change.device_id.0 == LOCAL_DEVICE)
        .count()
}

fn driver(h: &Harness) -> Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver> {
    h.session.clone() as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>
}

async fn settle(h: &Harness, paths: &[&str]) {
    let paths: BTreeSet<String> = paths.iter().map(|p| p.to_string()).collect();
    for _ in 0..3 {
        let attempt = h
            .convergence
            .reconcile_paths_directly(&driver(h), GROUP, paths.clone())
            .await
            .unwrap()
            .expect("sanity: the pass must actually run");
        if attempt.retry.is_empty() {
            return;
        }
    }
    panic!("{paths:?} did not settle");
}

fn copies_of_root_level(h: &Harness, source: &str) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(h.path(""))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| is_conflict_copy_path(name) && conflict_copy_source_path(name) == source)
        .collect();
    out.sort();
    out
}

/// Every name capture could be told about, then a full scan: none of it
/// may author anything.
async fn capture_everything(h: &Harness, names: &[&str]) {
    for name in names {
        h.capture(name).await;
    }
    h.scan();
}

/// This device's own File `a` is displaced by a peer's `a/x`, and later
/// returns when the peer deletes it. Neither move is captured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn structural_relocation_of_local_file_authors_no_change() {
    let h = Harness::new(true);
    std::fs::write(h.path("a"), b"this device's file a").unwrap();
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    let x = stored_version(&h, "scratch-x", b"the peer's a/x").await;
    let before = own_change_count(&h);

    remote_change(&h, vec![put("a/x", x)], &[]);
    settle(&h, &["a/x"]).await;

    assert!(std::fs::symlink_metadata(h.path("a")).unwrap().is_dir());
    assert_eq!(std::fs::read(h.path("a/x")).unwrap(), b"the peer's a/x");
    let copies = copies_of_root_level(&h, "a");
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert_eq!(std::fs::read(h.path(&copies[0])).unwrap(), b"this device's file a");
    capture_everything(&h, &["a", &copies[0], "a/x"]).await;
    assert_eq!(own_change_count(&h), before, "the relocation was captured as a change");

    remote_change(&h, vec![delete("a/x")], &[]);
    settle(&h, &["a/x"]).await;

    assert_eq!(std::fs::read(h.path("a")).unwrap(), b"this device's file a");
    capture_everything(&h, &["a", &copies[0], "a/x"]).await;
    assert_eq!(own_change_count(&h), before, "the move back was captured as a change");
}

/// A peer deletes explicit directory `d` while `d/f` lives: `d` stays as
/// the child's container, adopted as structural so it is never read as a
/// user's directory, and a full scan authors nothing for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remotely_deleted_explicit_dir_with_live_child_is_not_reauthored_by_full_scan() {
    let h = Harness::new(true);
    let f = stored_version(&h, "scratch-f", b"a child that outlives its directory").await;
    let directory = FileVersion::directory(None);
    remote_change(&h, vec![put("d", directory.version_hash), put("d/f", f)], &[directory]);
    settle(&h, &["d", "d/f"]).await;
    let before = own_change_count(&h);

    remote_change(&h, vec![delete("d")], &[]);
    settle(&h, &["d"]).await;

    assert!(h.path("d").is_dir());
    assert_eq!(std::fs::read(h.path("d/f")).unwrap(), b"a child that outlives its directory");
    let origin = h.state.sqlite().dag_structural_directory_origin(GROUP, "d").unwrap();
    let observed =
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&h.path("d")).ok();
    assert_eq!(
        origin.status(
            observed.as_ref(),
            yadorilink_root_authority::fs_identity::TimestampGranularity::Fine
        ),
        StructuralOriginStatus::Structural,
        "the kept directory must be adopted as structural"
    );
    capture_everything(&h, &["d", "d/f"]).await;
    assert_eq!(own_change_count(&h), before);
}

// --- Write-through: a user's operation on a relocated leaf ---
//
// The copy name a relocated File or Symlink sits under is the projection's,
// not an entry anyone authored. Deleting or editing it is the user acting
// on the source entry: `Delete(a)` / `Put(a)`, never an op at the copy
// name.

fn own_change_hashes(h: &Harness) -> BTreeSet<[u8; 32]> {
    h.state
        .change_history_repository()
        .dag_list_group_changes(GROUP)
        .unwrap()
        .iter()
        .filter(|change| change.device_id.0 == LOCAL_DEVICE)
        .map(|change| change.compute_hash().0)
        .collect()
}

/// The ops of every change this device authored after `before`.
fn own_ops_since(h: &Harness, before: &BTreeSet<[u8; 32]>) -> Vec<Op> {
    h.state
        .change_history_repository()
        .dag_list_group_changes(GROUP)
        .unwrap()
        .into_iter()
        .filter(|change| {
            change.device_id.0 == LOCAL_DEVICE && !before.contains(&change.compute_hash().0)
        })
        .flat_map(|change| change.ops)
        .collect()
}

fn op_paths(ops: &[Op]) -> Vec<String> {
    ops.iter()
        .map(|op| match op {
            Op::Put { path, .. } | Op::Delete { path } => path.as_str().to_string(),
            Op::Move { from, to, .. } => format!("{}->{}", from.as_str(), to.as_str()),
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
enum Leaf {
    File,
    Symlink,
}

fn write_leaf(h: &Harness, rel: &str, leaf: Leaf, body: &str) {
    let path = h.path(rel);
    let _ = std::fs::remove_file(&path);
    match leaf {
        Leaf::File => std::fs::write(&path, body).unwrap(),
        Leaf::Symlink => std::os::unix::fs::symlink(body, &path).unwrap(),
    }
}

fn read_leaf(h: &Harness, rel: &str, leaf: Leaf) -> String {
    match leaf {
        Leaf::File => String::from_utf8(std::fs::read(h.path(rel)).unwrap()).unwrap(),
        Leaf::Symlink => std::fs::read_link(h.path(rel)).unwrap().to_string_lossy().into_owned(),
    }
}

/// This device's own `a` (a File or Symlink), displaced to its copy name
/// by a peer's `a/x`. Returns the copy name.
async fn relocated_own_leaf(h: &Harness, leaf: Leaf) -> String {
    write_leaf(h, "a", leaf, "this device's a");
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    let x = stored_version(h, "scratch-x", b"the peer's a/x").await;
    remote_change(h, vec![put("a/x", x)], &[]);
    settle(h, &["a/x"]).await;
    assert!(std::fs::symlink_metadata(h.path("a")).unwrap().is_dir());
    let copies = copies_of_root_level(h, "a");
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert_eq!(read_leaf(h, &copies[0], leaf), "this device's a");
    copies[0].clone()
}

async fn retire(h: &Harness) {
    let attempt = h.convergence.retire_conflict_copies_only(GROUP).await.unwrap();
    assert!(
        matches!(attempt, RetirementAttempt::Settled { .. }),
        "the retirement pass must settle: {attempt:?}"
    );
}

fn desired(h: &Harness, path: &str) -> yadorilink_sync_sqlite::desired_state::DesiredPathState {
    h.state.desired_path_state(GROUP, path).unwrap()
}

async fn deleting_relocated_copy_deletes_original_entry_for(leaf: Leaf) {
    let h = Harness::new(true);
    let copy = relocated_own_leaf(&h, leaf).await;
    let before = own_change_hashes(&h);

    std::fs::remove_file(h.path(&copy)).unwrap();
    h.capture(&copy).await;

    let ops = own_ops_since(&h, &before);
    assert_eq!(op_paths(&ops), vec!["a".to_string()], "{leaf:?}: {ops:?}");
    assert!(matches!(ops[0], Op::Delete { .. }), "{leaf:?}: {ops:?}");
    assert_eq!(
        desired(&h, "a"),
        yadorilink_sync_sqlite::desired_state::DesiredPathState::StructuralDirectory,
        "{leaf:?}: a keeps only its descendant's directory"
    );
    let before = own_change_hashes(&h);
    settle(&h, &["a", "a/x"]).await;
    assert!(copies_of_root_level(&h, "a").is_empty(), "{leaf:?}");
    assert_eq!(std::fs::read(h.path("a/x")).unwrap(), b"the peer's a/x");
    capture_everything(&h, &["a", &copy, "a/x"]).await;
    assert_eq!(own_ops_since(&h, &before), Vec::<Op>::new(), "{leaf:?}");
}

/// Deleting the copy a relocated File sits under deletes
/// the File's own entry, `a`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_relocated_copy_deletes_original_entry() {
    deleting_relocated_copy_deletes_original_entry_for(Leaf::File).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_relocated_symlink_copy_deletes_original_entry() {
    deleting_relocated_copy_deletes_original_entry_for(Leaf::Symlink).await;
}

async fn editing_relocated_copy_writes_through_for(leaf: Leaf) {
    let h = Harness::new(true);
    let copy = relocated_own_leaf(&h, leaf).await;
    let before = own_change_hashes(&h);

    write_leaf(&h, &copy, leaf, "edited through the copy");
    h.capture(&copy).await;

    let ops = own_ops_since(&h, &before);
    assert_eq!(op_paths(&ops), vec!["a".to_string()], "{leaf:?}: {ops:?}");
    let Op::Put { version, origin: PutOrigin::Direct, .. } = &ops[0] else {
        panic!("{leaf:?}: expected a direct Put of a: {ops:?}");
    };
    let heads = h.convergence.combined_heads(GROUP, "a", None).unwrap();
    assert_eq!(heads.len(), 1, "{leaf:?}: the edit supersedes the relocated head: {heads:?}");
    assert_eq!(heads[0].content.as_ref().unwrap().version_hash, version.0, "{leaf:?}");
    assert_eq!(
        desired(&h, "a"),
        yadorilink_sync_sqlite::desired_state::DesiredPathState::StructuralDirectory,
        "{leaf:?}"
    );

    // The new content has a copy name of its own: reconcile places it
    // there, and the retirement pass (run whenever the frontier moves)
    // retires the old name, which no change carries and the namespace no
    // longer places anything at.
    let before = own_change_hashes(&h);
    settle(&h, &["a", "a/x"]).await;
    retire(&h).await;
    let copies = copies_of_root_level(&h, "a");
    assert_eq!(copies.len(), 1, "{leaf:?}: {copies:?}");
    assert_eq!(
        copies[0],
        yadorilink_replica_engine::namespace::first_copy_name("a", &heads[0]),
        "{leaf:?}"
    );
    assert_eq!(read_leaf(&h, &copies[0], leaf), "edited through the copy", "{leaf:?}");
    capture_everything(&h, &["a", &copy, &copies[0], "a/x"]).await;
    assert_eq!(own_ops_since(&h, &before), Vec::<Op>::new(), "{leaf:?}");
}

/// Editing the copy a relocated File sits under writes the
/// new content to `a`; the copy name is never authored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn editing_relocated_copy_writes_through() {
    editing_relocated_copy_writes_through_for(Leaf::File).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn editing_relocated_symlink_copy_writes_through() {
    editing_relocated_copy_writes_through_for(Leaf::Symlink).await;
}

/// A peer's explicit Directory `a`, concurrent with this device's
/// own File or Symlink `a`, keeps its path and the leaf sits at its copy
/// name. Deleting the copy deletes the leaf's entry and only it: the
/// Directory stays explicit.
async fn deleting_leaf_beside_explicit_directory_keeps_the_directory_for(leaf: Leaf) {
    let h = Harness::new(true);
    let x = stored_version(&h, "scratch-x", b"the peer's a/x").await;
    let concurrent_parents = h.state.dag_group_heads(GROUP).unwrap();
    write_leaf(&h, "a", leaf, "this device's a");
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    let directory = FileVersion::directory(None);
    h.state
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, &directory)?;
            yadorilink_sync_sqlite::dag_store::emit_local_change_onto(
                conn,
                GROUP,
                concurrent_parents.clone(),
                vec![put("a", directory.version_hash), put("a/x", x)],
                &remote_emitter(),
            )
        })
        .unwrap();
    settle(&h, &["a", "a/x"]).await;
    assert!(std::fs::symlink_metadata(h.path("a")).unwrap().is_dir(), "{leaf:?}");
    let copies = copies_of_root_level(&h, "a");
    assert_eq!(copies.len(), 1, "{leaf:?}: {copies:?}");
    let copy = copies[0].clone();
    assert!(
        h.convergence.combined_heads(GROUP, &copy, None).unwrap().is_empty(),
        "{leaf:?}: sanity: the copy name is the projection's, not an authored entry"
    );
    let before = own_change_hashes(&h);

    std::fs::remove_file(h.path(&copy)).unwrap();
    h.capture(&copy).await;

    let ops = own_ops_since(&h, &before);
    assert_eq!(op_paths(&ops), vec!["a".to_string()], "{leaf:?}: {ops:?}");
    assert!(matches!(ops[0], Op::Delete { .. }), "{leaf:?}: {ops:?}");
    assert_eq!(
        desired(&h, "a"),
        yadorilink_sync_sqlite::desired_state::DesiredPathState::ExplicitDirectory {
            version: directory.version_hash
        },
        "{leaf:?}: the Directory keeps its path and its entry"
    );
    settle(&h, &["a", "a/x"]).await;
    assert!(copies_of_root_level(&h, "a").is_empty(), "{leaf:?}");
    assert!(std::fs::symlink_metadata(h.path("a")).unwrap().is_dir(), "{leaf:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_file_beside_explicit_directory_keeps_the_directory() {
    deleting_leaf_beside_explicit_directory_keeps_the_directory_for(Leaf::File).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_symlink_beside_explicit_directory_keeps_the_directory() {
    deleting_leaf_beside_explicit_directory_keeps_the_directory_for(Leaf::Symlink).await;
}

/// Editing the leaf beside an explicit Directory writes the
/// leaf's entry, concurrent with the Directory, which keeps its path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn editing_file_beside_explicit_directory_keeps_the_directory() {
    let h = Harness::new(true);
    let x = stored_version(&h, "scratch-x", b"the peer's a/x").await;
    let concurrent_parents = h.state.dag_group_heads(GROUP).unwrap();
    std::fs::write(h.path("a"), b"this device's a").unwrap();
    assert!(matches!(h.capture("a").await, LocalChangeOutcome::FileChanged(_)));
    let directory = FileVersion::directory(None);
    h.state
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, &directory)?;
            yadorilink_sync_sqlite::dag_store::emit_local_change_onto(
                conn,
                GROUP,
                concurrent_parents.clone(),
                vec![put("a", directory.version_hash), put("a/x", x)],
                &remote_emitter(),
            )
        })
        .unwrap();
    settle(&h, &["a", "a/x"]).await;
    let copies = copies_of_root_level(&h, "a");
    assert_eq!(copies.len(), 1, "{copies:?}");
    let before = own_change_hashes(&h);

    std::fs::write(h.path(&copies[0]), b"edited beside the directory").unwrap();
    h.capture(&copies[0]).await;

    let ops = own_ops_since(&h, &before);
    assert_eq!(op_paths(&ops), vec!["a".to_string()], "{ops:?}");
    assert!(matches!(ops[0], Op::Put { .. }), "{ops:?}");
    assert_eq!(
        desired(&h, "a"),
        yadorilink_sync_sqlite::desired_state::DesiredPathState::ExplicitDirectory {
            version: directory.version_hash
        }
    );
    settle(&h, &["a", "a/x"]).await;
    retire(&h).await;
    let copies = copies_of_root_level(&h, "a");
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert_eq!(std::fs::read(h.path(&copies[0])).unwrap(), b"edited beside the directory");
    assert!(std::fs::symlink_metadata(h.path("a")).unwrap().is_dir());
}

/// The distinction: a copy some change authored as an entry of its own is
/// that entry. Deleting it deletes it, at its own name; `a` is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_an_authored_conflict_copy_deletes_the_copy_itself() {
    let h = Harness::new(true);
    let copy = relocated_own_leaf(&h, Leaf::File).await;
    let authored = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
        "a",
        "device-remote",
        0,
        &[0xAB; 32],
    );
    assert_ne!(authored, copy);
    let body = stored_version(&h, "scratch-authored", b"an authored conflict copy").await;
    remote_change(&h, vec![put(&authored, body)], &[]);
    settle(&h, &[&authored]).await;
    assert_eq!(std::fs::read(h.path(&authored)).unwrap(), b"an authored conflict copy");
    let before = own_change_hashes(&h);

    std::fs::remove_file(h.path(&authored)).unwrap();
    h.capture(&authored).await;

    let ops = own_ops_since(&h, &before);
    assert_eq!(op_paths(&ops), vec![authored.clone()], "{ops:?}");
    assert!(matches!(ops[0], Op::Delete { .. }), "{ops:?}");
    assert_eq!(read_leaf(&h, &copy, Leaf::File), "this device's a", "the relocated leaf stays");
    assert!(
        !h.convergence.combined_heads(GROUP, "a", None).unwrap().is_empty(),
        "a's entry is untouched"
    );
}

/// The batched route (one debounced flush) writes through exactly as the
/// immediate one does, for a delete and for an edit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flushed_batch_writes_relocated_copy_operations_through() {
    let h = Harness::new(true);
    let copy = relocated_own_leaf(&h, Leaf::File).await;
    let before = own_change_hashes(&h);
    std::fs::write(h.path(&copy), b"edited through the copy, batched").unwrap();
    h.capture_flush(&[&copy]).await;
    let ops = own_ops_since(&h, &before);
    assert_eq!(op_paths(&ops), vec!["a".to_string()], "{ops:?}");
    assert!(matches!(ops[0], Op::Put { .. }), "{ops:?}");

    let before = own_change_hashes(&h);
    std::fs::remove_file(h.path(&copy)).unwrap();
    h.capture_flush(&[&copy]).await;
    let ops = own_ops_since(&h, &before);
    assert_eq!(op_paths(&ops), vec!["a".to_string()], "{ops:?}");
    assert!(matches!(ops[0], Op::Delete { .. }), "{ops:?}");
}

/// A full scan that finds the relocated copy gone or changed does not
/// author the copy name either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_scan_writes_relocated_copy_operations_through() {
    let h = Harness::new(true);
    let copy = relocated_own_leaf(&h, Leaf::File).await;
    let before = own_change_hashes(&h);
    std::fs::write(h.path(&copy), b"edited while nothing watched").unwrap();
    h.scan();
    let ops = own_ops_since(&h, &before);
    assert!(!op_paths(&ops).contains(&copy), "the scan authored the copy name: {ops:?}");
    // The scan journals the copy dirty; the re-drive authors it, at `a`.
    h.redrive().await;
    let ops = own_ops_since(&h, &before);
    assert_eq!(op_paths(&ops), vec!["a".to_string()], "{ops:?}");
    assert!(matches!(ops[0], Op::Put { .. }), "{ops:?}");

    let before = own_change_hashes(&h);
    std::fs::remove_file(h.path(&copy)).unwrap();
    h.scan();
    let ops = own_ops_since(&h, &before);
    assert!(!op_paths(&ops).contains(&copy), "the scan authored the copy name: {ops:?}");
    h.redrive().await;
    let ops = own_ops_since(&h, &before);
    assert_eq!(op_paths(&ops), vec!["a".to_string()], "{ops:?}");
    assert!(matches!(ops[0], Op::Delete { .. }), "{ops:?}");
}

fn copies_in(h: &Harness, dir: &str, source: &str) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(h.path(dir))
        .unwrap()
        .map(|entry| format!("{dir}/{}", entry.unwrap().file_name().to_string_lossy()))
        .filter(|name| is_conflict_copy_path(name) && conflict_copy_source_path(name) == source)
        .collect();
    out.sort();
    out
}

/// This device's explicit directory `p` holding its own File `p/a`,
/// displaced to its copy name by a peer's `p/a/x`. Returns the copy name.
async fn relocated_own_file_in_a_folder(h: &Harness) -> String {
    std::fs::create_dir(h.path("p")).unwrap();
    assert!(matches!(h.capture("p").await, LocalChangeOutcome::FileChanged(_)));
    std::fs::write(h.path("p/a"), b"this device's p/a").unwrap();
    assert!(matches!(h.capture("p/a").await, LocalChangeOutcome::FileChanged(_)));
    let x = stored_version(h, "scratch-x", b"the peer's p/a/x").await;
    remote_change(h, vec![put("p/a/x", x)], &[]);
    settle(h, &["p", "p/a", "p/a/x"]).await;
    assert!(std::fs::symlink_metadata(h.path("p/a")).unwrap().is_dir());
    let copies = copies_in(h, "p", "p/a");
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert_eq!(std::fs::read(h.path(&copies[0])).unwrap(), b"this device's p/a");
    copies[0].clone()
}

/// `rm -rf p` over a relocated copy deletes the entry the copy is, `p/a`;
/// the copy name is never authored, and nothing comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recursive_delete_writes_a_relocated_copy_through() {
    let h = Harness::new(true);
    let copy = relocated_own_file_in_a_folder(&h).await;
    let before = own_change_hashes(&h);

    std::fs::remove_dir_all(h.path("p")).unwrap();
    h.capture("p").await;

    let ops = own_ops_since(&h, &before);
    let paths: BTreeSet<String> = op_paths(&ops).into_iter().collect();
    assert_eq!(paths, ["p", "p/a", "p/a/x"].into_iter().map(String::from).collect(), "{ops:?}");
    assert!(ops.iter().all(|op| matches!(op, Op::Delete { .. })), "{ops:?}");
    assert!(!paths.contains(&copy));
    for path in ["p", "p/a", "p/a/x"] {
        assert_eq!(
            desired(&h, path),
            yadorilink_sync_sqlite::desired_state::DesiredPathState::Absent,
            "{path} must stay deleted"
        );
    }
    settle(&h, &["p", "p/a", "p/a/x"]).await;
    assert!(std::fs::symlink_metadata(h.path("p")).is_err(), "the deleted folder came back");
}

/// `mv p q` over a relocated copy moves the entry the copy is: `p/a` is
/// deleted and `q/a` put, and no copy name is authored at either side.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_rename_writes_a_relocated_copy_through() {
    let h = Harness::new(true);
    let copy = relocated_own_file_in_a_folder(&h).await;
    let before = own_change_hashes(&h);

    std::fs::rename(h.path("p"), h.path("q")).unwrap();
    h.capture_flush(&["p", "q"]).await;

    let ops = own_ops_since(&h, &before);
    let deleted: BTreeSet<String> = ops
        .iter()
        .filter_map(|op| match op {
            Op::Delete { path } => Some(path.as_str().to_string()),
            _ => None,
        })
        .collect();
    let put: BTreeSet<String> = ops
        .iter()
        .filter_map(|op| match op {
            Op::Put { path, .. } => Some(path.as_str().to_string()),
            _ => None,
        })
        .collect();
    let set = |paths: &[&str]| paths.iter().map(|p| p.to_string()).collect::<BTreeSet<_>>();
    assert_eq!(deleted, set(&["p", "p/a", "p/a/x"]), "{ops:?}");
    assert_eq!(put, set(&["q", "q/a", "q/a/x"]), "{ops:?}");
    assert!(!op_paths(&ops).iter().any(|path| is_conflict_copy_path(path)), "{copy}: {ops:?}");
    assert_eq!(
        desired(&h, "p/a"),
        yadorilink_sync_sqlite::desired_state::DesiredPathState::Absent,
        "the old entry must not come back"
    );
    assert_eq!(
        desired(&h, "q/a"),
        yadorilink_sync_sqlite::desired_state::DesiredPathState::StructuralDirectory,
        "the moved file sits beside q/a/x again"
    );
}

/// The copy is replaced by a directory of the same name: the file's
/// removal deletes the entry it was, `a`, and the directory is a new entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_replacing_a_relocated_copy_deletes_its_entry() {
    let h = Harness::new(true);
    let copy = relocated_own_leaf(&h, Leaf::File).await;
    let before = own_change_hashes(&h);

    std::fs::remove_file(h.path(&copy)).unwrap();
    std::fs::create_dir(h.path(&copy)).unwrap();
    h.capture(&copy).await;

    let ops = own_ops_since(&h, &before);
    assert!(
        ops.iter().any(|op| matches!(op, Op::Delete { path } if path.as_str() == "a")),
        "the replaced file's entry must be deleted: {ops:?}"
    );
    assert_eq!(
        desired(&h, "a"),
        yadorilink_sync_sqlite::desired_state::DesiredPathState::StructuralDirectory,
        "a keeps only its descendant's directory"
    );
}

/// A peer's later write of `a`, descending from the one the copy shows, is
/// admitted before the reconcile moves the copy. Deleting the copy in that
/// window is still deleting `a`'s entry, concurrent with the peer's write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_copy_the_reconcile_has_not_caught_up_with_writes_through() {
    let h = Harness::new(true);
    let copy = relocated_own_leaf(&h, Leaf::File).await;
    let newer = stored_version(&h, "scratch-newer", b"the peer's newer a").await;
    remote_change(&h, vec![put("a", newer)], &[]);
    let before = own_change_hashes(&h);

    std::fs::remove_file(h.path(&copy)).unwrap();
    h.capture(&copy).await;

    let ops = own_ops_since(&h, &before);
    assert_eq!(op_paths(&ops), vec!["a".to_string()], "{ops:?}");
    assert!(matches!(ops[0], Op::Delete { .. }), "{ops:?}");
    let heads = h.convergence.combined_heads(GROUP, "a", None).unwrap();
    assert!(
        heads.iter().any(|head| head.content.as_ref().is_some_and(|c| c.version_hash == newer.0)),
        "the peer's write, which the copy never showed, stays live: {heads:?}"
    );
}
