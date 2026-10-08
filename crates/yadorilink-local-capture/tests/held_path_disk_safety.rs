//! A path held for reconciliation belongs to no row this device placed: the
//! object on disk there is an edit native cannot author (its own bucket at the
//! path is full), so nothing may author it, delete it, or overwrite it until
//! the reconciliation pass has looked at it. These tests drive that pass
//! through every window a crash or a concurrent user write can open around it,
//! and check the copy name an entry takes when a directory holds its name.

use std::sync::Arc;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::held_path_reconcile::{
    set_reconcile_step_hook_for_test, ReconcileStepForTest,
};
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_local_capture::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_local_storage::{chunk_file, SegmentBlockStore};
use yadorilink_replica_domain::admission::LocalAuthorKey;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};
use yadorilink_root_authority::root_identity::VerifiedRoot;

const GROUP: &str = "group-1";

const CURRENT: &[u8] = b"the version the index holds at the path\n";
const EDIT: &[u8] = b"an edit this device's full own bucket at the path refuses\n";

struct Fixture {
    state: Arc<ReplicaCoordinator>,
    store: Arc<SegmentBlockStore>,
    processor: LocalChangeProcessor,
    root: std::path::PathBuf,
    _root_dir: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let _ = state.link_repository().add_link(&root.to_string_lossy(), GROUP);
        VerifiedRoot::open(&root, GROUP, state.as_ref()).unwrap();
        // The processor signs what it captures, so every row it indexes names
        // the native head it was authored as.
        let processor = LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "device-a".to_string(),
            Arc::new(RootLease::for_tests()),
        )
        .with_change_emitter(Arc::new(LocalAuthorKey::for_tests(
            "device-a",
            ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]),
        )));
        Self { state, store, processor, root, _root_dir: root_dir, _store_dir: store_dir }
    }

    /// The block list `content` chunks to, with its blocks in the store.
    fn blocks(&self, content: &[u8]) -> Vec<BlockInfo> {
        let scratch = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(scratch.path(), content).unwrap();
        chunk_file(self.store.as_ref(), scratch.path()).unwrap()
    }

    /// `path` as this device has it: `content` on disk, captured into the
    /// index, and `Present`.
    async fn hydrated(&self, path: &str, content: &[u8]) {
        std::fs::write(self.root.join(path), content).unwrap();
        self.event(path).await;
        self.state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                path,
                MaterializationState::Present,
                &RootCommitPermit::for_tests(),
            )
            .unwrap();
        let row = self.state.file_index_repository().get_file(GROUP, path).unwrap().unwrap();
        assert_eq!(row.size, content.len() as u64, "the fixture's own capture must index {path}");
    }

    async fn event(&self, path: &str) -> LocalChangeOutcome {
        self.processor
            .process_event(
                GROUP,
                &self.root,
                &FsChangeEvent {
                    path: self.root.join(path),
                    kind: FsChangeKind::CreatedOrModified,
                },
            )
            .await
            .unwrap()
    }

    /// Holds `path` for a local edit this replica cannot author there.
    fn hold(&self, path: &str) {
        self.state.held_path_repository().hold_unauthorable_local_edit(GROUP, path).unwrap();
    }

    /// One startup repair pass, which reconciles every held path first.
    fn repair(&self) {
        yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            self.state.as_ref(),
            self.store.as_ref(),
            &self.root,
            GROUP,
            yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    }

    /// Every entry directly under the root other than the root marker.
    fn disk_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| !name.starts_with('.'))
            .collect();
        names.sort();
        names
    }

    /// Every file directly under the root other than `path` and the root
    /// marker, with its bytes.
    fn preserved_besides(&self, path: &str) -> Vec<Vec<u8>> {
        self.disk_entries()
            .into_iter()
            .filter(|name| name != path)
            .map(|name| std::fs::read(self.root.join(&name)).unwrap())
            .collect()
    }

    /// Whether `path` is a `Remote` row's: no object stands in the user tree.
    fn is_remote_with_no_object(&self, path: &str) -> bool {
        std::fs::symlink_metadata(self.root.join(path)).is_err()
            && self
                .state
                .materialization_state_repository()
                .get_materialization_state(GROUP, path)
                .unwrap()
                == Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
    }

    fn holds(&self) -> Vec<String> {
        self.state.held_path_repository().held_paths(GROUP).unwrap()
    }

    fn indexed_blocks(&self, path: &str) -> Option<Vec<BlockInfo>> {
        self.state
            .file_index_repository()
            .get_file(GROUP, path)
            .unwrap()
            .filter(|row| !row.deleted)
            .map(|row| row.blocks)
    }
}

/// Saves `content` at `path` the way an editor does: written beside it and
/// renamed over it, so the path gets a new object rather than new bytes.
fn save_atomically(path: &std::path::Path, content: &[u8]) {
    let saved = path.with_file_name("editor-save.swp");
    std::fs::write(&saved, content).unwrap();
    std::fs::rename(&saved, path).unwrap();
}

/// A local edit this device cannot author at its path is held with no prior
/// placement. The reconciliation preserves the edit under a conflict-copy
/// name, which the scan captures as a new file, and puts the path's current
/// version back: nothing is superseded unseen and nothing is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unauthorable_local_edit_is_preserved_and_the_path_restored() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    std::fs::write(fx.root.join("doc.txt"), EDIT).unwrap();

    fx.hold("doc.txt");
    fx.repair();

    // No object: the row is `Remote`, and the released path's projection
    // obligation brings its content as policy says.
    assert!(fx.is_remote_with_no_object("doc.txt"), "the path's current version is back");
    assert!(fx.holds().is_empty(), "the hold is released");
    let entries = fx.disk_entries();
    let preserved = fx.preserved_besides("doc.txt");
    assert_eq!(
        preserved,
        vec![EDIT.to_vec()],
        "the edit was not preserved exactly once: {entries:?}"
    );
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(CURRENT)));
}

/// While the path is held, the bytes on disk are not an edit anyone may
/// author: a watcher event for them captures nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_paths_bytes_are_not_captured() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    std::fs::write(fx.root.join("doc.txt"), EDIT).unwrap();
    fx.hold("doc.txt");

    assert_eq!(fx.event("doc.txt").await, LocalChangeOutcome::None);
    let minted = fx.processor.scan_existing_files(GROUP, &fx.root).unwrap();
    assert!(
        minted.iter().all(|record| record.path != "doc.txt"),
        "the scan captured a held path: {minted:?}"
    );
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(CURRENT)));
}

/// A crash after reconciliation emptied the path (moved the edit aside) but
/// before it released the hold: the next pass finds nothing there and
/// releases it, and the empty path was never read as a deletion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_the_path_was_emptied_is_finished_by_the_next_pass() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    fx.hold("doc.txt");
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();

    let before_repair = fx.processor.scan_existing_files(GROUP, &fx.root).unwrap();
    assert!(before_repair.is_empty(), "an emptied held path was tombstoned: {before_repair:?}");

    fx.repair();

    assert!(fx.is_remote_with_no_object("doc.txt"));
    assert!(fx.disk_entries().is_empty(), "nothing is placed: {:?}", fx.disk_entries());
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(CURRENT)));
}

/// Once reconciled, the path is an ordinary one again: an edit made after
/// that is captured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_after_reconciliation_is_captured() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    fx.hold("doc.txt");
    fx.repair();

    let edit: &[u8] = b"an edit made after the path was reconciled\n";
    std::fs::write(fx.root.join("doc.txt"), edit).unwrap();

    match fx.event("doc.txt").await {
        LocalChangeOutcome::FileChanged(record) => assert_eq!(record.blocks, fx.blocks(edit)),
        other => panic!("an edit of the reconciled path was not captured: {other:?}"),
    }
}

/// Reconciliation found an edit and is about to move it aside -- and the user
/// saves over the path first. Whatever is at the path by the time it acts is
/// the user's save, and it is preserved, not discarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_save_landing_after_the_edit_was_classified_is_preserved() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    std::fs::write(fx.root.join("doc.txt"), EDIT).unwrap();
    fx.hold("doc.txt");
    let save: &[u8] = b"a save made while reconciliation was hashing the edit\n";
    let mut saved = false;
    let _hook = set_reconcile_step_hook_for_test(move |step, path| {
        if step == ReconcileStepForTest::Classified && !saved {
            saved = true;
            save_atomically(path, save);
        }
    });

    fx.repair();

    assert_eq!(
        fx.preserved_besides("doc.txt"),
        vec![save.to_vec()],
        "the save was not preserved exactly once"
    );
    assert!(fx.is_remote_with_no_object("doc.txt"));
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(CURRENT)));
}

/// The path was found empty, so reconciliation is about to release its hold
/// -- and the user creates a file at the path first. Releasing must not leave
/// that file unexamined: the hold stays, and the next pass preserves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_created_before_the_hold_is_released_is_preserved_not_adopted() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    fx.hold("doc.txt");
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();
    let created: &[u8] = b"a file the user created at the emptied path\n";
    let mut wrote = false;
    let _hook = set_reconcile_step_hook_for_test(move |step, path| {
        if step == ReconcileStepForTest::ReleasingEntry && !wrote {
            wrote = true;
            save_atomically(path, created);
        }
    });

    fx.repair();
    fx.repair();

    assert_eq!(
        fx.preserved_besides("doc.txt"),
        vec![created.to_vec()],
        "the created file was not preserved exactly once"
    );
    assert!(fx.is_remote_with_no_object("doc.txt"));
    assert!(fx.holds().is_empty(), "the path is still held after a pass found it empty again");
}

/// A crash after reconciliation took the object at a held path aside to
/// examine it, but before it settled it: the next pass settles the taken
/// object first. A user's save taken that way is preserved, not discarded
/// with the reserved name it was left under.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_the_object_was_taken_aside_preserves_a_save_it_took() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    fx.hold("doc.txt");
    let save: &[u8] = b"a save the crashed pass had taken aside\n";
    let taken = yadorilink_filesystem_sync::held_path_reconcile::taken_object_path_for_test(
        &fx.root, "doc.txt",
    );
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();
    std::fs::write(&taken, save).unwrap();

    fx.repair();

    assert!(!taken.exists(), "the taken object was left under its reserved name");
    assert_eq!(
        fx.preserved_besides("doc.txt"),
        vec![save.to_vec()],
        "the taken save was not preserved exactly once"
    );
    assert!(fx.is_remote_with_no_object("doc.txt"));
}

/// The first free numbered copy name of the head at `path`: the name the live
/// reconciler gives an entry that a directory keeps out of its own path.
fn copy_name_of(fx: &Fixture, path: &str) -> String {
    let heads = fx
        .state
        .database()
        .read(|conn| {
            yadorilink_sync_sqlite::native_store::native_heads_at(
                conn,
                &FolderGroupId(GROUP.to_owned()),
                &SyncPath(path.to_owned()),
            )
        })
        .unwrap();
    assert_eq!(heads.len(), 1, "the fixture authored one head at {path}");
    yadorilink_replica_domain::native_resolver::numbered_copy_name(
        path,
        heads[0].payload.version.0,
        1,
    )
}

/// A directory the user made holds the name a held entry needs. The
/// directory is kept, and the entry goes to its copy name beside it, in the
/// index and on disk: the index never names a file where the disk has a
/// directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_entry_over_a_users_directory_goes_to_its_copy_name() {
    let fx = Fixture::new();
    fx.hydrated("a", CURRENT).await;
    let expected = copy_name_of(&fx, "a");
    fx.hold("a");
    std::fs::remove_file(fx.root.join("a")).unwrap();
    std::fs::create_dir(fx.root.join("a")).unwrap();
    std::fs::write(fx.root.join("a/mine"), b"the user's own").unwrap();

    fx.repair();
    fx.repair();

    assert_eq!(std::fs::read(fx.root.join("a/mine")).unwrap(), b"the user's own");
    assert_eq!(fx.indexed_blocks("a"), None, "the index names a file where a directory is");
    assert_eq!(fx.indexed_blocks(&expected), Some(fx.blocks(CURRENT)));
    assert!(fx.is_remote_with_no_object(&expected), "{:?}", fx.disk_entries());
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// A pass that crashes right after it moved a held entry's row to its copy
/// name beside a directory of the user's -- the relocation and the release of
/// the entry's hold commit together -- must not leave that directory
/// unrecorded: nothing would ever bring the path back, and the offline scan
/// would author the user's untracked directory as an explicit `Directory a`
/// over the file `a`, which an uninterrupted pass never does. The directory's
/// retained record commits with the relocation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_right_after_an_entry_is_relocated_beside_a_users_directory_authors_nothing() {
    let fx = Fixture::new();
    fx.hydrated("a", CURRENT).await;
    fx.hold("a");
    std::fs::remove_file(fx.root.join("a")).unwrap();
    std::fs::create_dir(fx.root.join("a")).unwrap();
    std::fs::write(fx.root.join("a/mine"), b"the user's own").unwrap();
    {
        let _hook = set_reconcile_step_hook_for_test(|step, _| {
            if step == ReconcileStepForTest::EntryRelocated {
                panic!("crash right after the relocation commits");
            }
        });
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fx.repair()));
        assert!(crashed.is_err());
    }
    fx.repair();
    fx.repair();

    assert_eq!(
        fx.state.sqlite().retained_directory_reason(GROUP, "a").unwrap().as_deref(),
        Some(yadorilink_sync_sqlite::structural_origin::RETAINED_UNTRACKED_CONTENT),
        "the user's directory holding the entry's name is not recorded as retained"
    );
    let minted: Vec<String> = fx
        .processor
        .scan_existing_files(GROUP, &fx.root)
        .unwrap()
        .into_iter()
        .map(|record| record.path)
        .collect();
    assert_eq!(minted, vec!["a/mine".to_string()], "only the user's own file is new content");
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}
