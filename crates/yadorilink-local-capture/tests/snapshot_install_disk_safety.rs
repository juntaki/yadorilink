//! A HistoryBase snapshot install replaces a group's index rows in one
//! transaction and touches no file. For every path whose installed row
//! differs from the one it replaced, the bytes on disk still belong to the
//! replaced row -- or to an edit made on top of it that local capture never
//! saw -- until something reconciles the path. These tests pin what local
//! capture, the offline-delete scan and the authoring seam may do with such
//! a path in each window around an install: before any reconciliation (the
//! install committed and the daemon crashed or has not got to it yet),
//! partway through one, and after it.

#![cfg(unix)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_local_capture::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_local_storage::{chunk_file, SegmentBlockStore};
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::file::{
    BlockInfo, FileMeta, FileRecord, FileVersion, RecordKind, VersionBlock,
};
use yadorilink_replica_domain::ids::{BlockHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::session_state::{MaterializationState, PreparedLocalMutation};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_replica_engine::compaction::Checkpoint;
use yadorilink_replica_engine::rebootstrap::SnapshotManifest;
use yadorilink_replica_engine::rebootstrap_snapshot::{
    RebootstrapSnapshot, SnapshotAuthorState, SnapshotFile, SnapshotVersionState,
};
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};
use yadorilink_root_authority::root_identity::VerifiedRoot;

const GROUP: &str = "group-1";

struct Fixture {
    state: Arc<ReplicaCoordinator>,
    store: Arc<SegmentBlockStore>,
    processor: LocalChangeProcessor,
    root: std::path::PathBuf,
    /// The checkpoint of the last install, which the next one extends.
    installed_checkpoint: std::sync::Mutex<Option<[u8; 32]>>,
    /// The frontier change every installed base carries; see
    /// [`Self::prepare_install`].
    base_author: yadorilink_replica_domain::change::Change,
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
        let processor = LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "device-a".to_string(),
            Arc::new(RootLease::for_tests()),
        );
        Self {
            state,
            store,
            processor,
            root,
            installed_checkpoint: std::sync::Mutex::new(None),
            base_author: create_signed_for_tests(
                Vec::new(),
                0,
                DeviceId("device-base-author".to_string()),
                FolderGroupId(GROUP.to_string()),
                vec![Op::Delete { path: SyncPath("base-author-marker".to_string()) }],
                &SigningKey::from_bytes(&[13u8; 32]),
            ),
            _root_dir: root_dir,
            _store_dir: store_dir,
        }
    }

    /// The block list `content` chunks to, with its blocks in the store.
    fn blocks(&self, content: &[u8]) -> Vec<BlockInfo> {
        let scratch = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(scratch.path(), content).unwrap();
        chunk_file(self.store.as_ref(), scratch.path()).unwrap()
    }

    /// `path` as this device had it before the install: `content` on disk,
    /// captured into the index, and `Hydrated`.
    async fn hydrated(&self, path: &str, content: &[u8]) {
        let file_path = self.root.join(path);
        std::fs::write(&file_path, content).unwrap();
        self.event(path).await;
        self.state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                path,
                MaterializationState::Hydrated,
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

    fn snapshot_row(&self, path: &str, content: &[u8]) -> SnapshotFile {
        SnapshotFile {
            record: FileRecord {
                path: path.to_string(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: self.blocks(content),
                deleted: false,
            },
            version_seq: 7,
            state: SnapshotVersionState::Current,
            origin_device_id: Some("device-b".to_string()),
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: None,
            xattrs: Vec::new(),
            authoring_change_hash: None,
        }
    }

    /// Installs a HistoryBase whose snapshot carries exactly `files`,
    /// extending the one installed last.
    fn install(&self, files: Vec<SnapshotFile>) {
        let (manifest, snapshot) = self.prepare_install(files);
        self.state.install_base_for_tests(&manifest, &snapshot).unwrap();
    }

    /// The manifest and encoded snapshot of the install [`Self::install`]
    /// would perform, for a test that performs it somewhere else. The
    /// fixture counts it as installed.
    ///
    /// Every base carries the same frontier change, by an author no test
    /// emits under, and it authors each of the base's rows: a group with a
    /// base refuses a current row that names no author. The base carries
    /// that change's evidence beside it, as every base installed by the
    /// atomic epoch reset must: no change body stays behind to vouch for a
    /// row.
    fn prepare_install(&self, files: Vec<SnapshotFile>) -> (SnapshotManifest, Vec<u8>) {
        self.prepare_install_with_heads(files, &[])
    }

    /// The version hash of `file`'s row, as the index derives it.
    fn row_version(file: &SnapshotFile) -> yadorilink_replica_domain::ids::VersionHash {
        FileVersion::from_index_row(
            file.record.blocks.clone(),
            file.record.size,
            file.record.mtime_unix_nanos,
            file.record_kind,
            file.unix_mode,
            file.symlink_target.clone(),
            file.xattrs.clone(),
        )
        .version_hash
    }

    /// The head [`Self::prepare_install_with_heads`] gives `file` under
    /// `naming_device_id`, as the live path frontier carries it.
    fn frontier_head(
        &self,
        file: &SnapshotFile,
        naming_device_id: &str,
    ) -> yadorilink_replica_engine::conflict::PathHead {
        yadorilink_replica_engine::conflict::PathHead {
            change_hash: self.base_author.compute_hash().0,
            lamport: self.base_author.lamport,
            device_id: self.base_author.device_id.as_str().to_string(),
            naming_device_id: naming_device_id.to_string(),
            content: Some(yadorilink_replica_engine::conflict::PathHeadContent {
                version_hash: Self::row_version(file).0,
                mtime_unix_nanos: 0,
            }),
        }
    }

    /// [`Self::prepare_install`], with the base's head summary carrying one
    /// head for each `(path, naming_device_id)`: the base author's write of
    /// that path's row, named for `naming_device_id` (another device's, for
    /// content carried forward on its behalf).
    fn prepare_install_with_heads(
        &self,
        mut files: Vec<SnapshotFile>,
        heads: &[(&str, &str)],
    ) -> (SnapshotManifest, Vec<u8>) {
        let group = FolderGroupId(GROUP.to_string());
        let author = &self.base_author;
        let author_hash = author.compute_hash();
        for file in &mut files {
            file.authoring_change_hash = Some(author_hash);
        }
        let path_heads = heads
            .iter()
            .map(|(path, naming)| {
                let file = files.iter().find(|file| file.record.path == *path).unwrap();
                yadorilink_replica_engine::rebootstrap_snapshot::SnapshotPathHead {
                    path: path.to_string(),
                    change_hash: author_hash,
                    device_id: author.device_id.as_str().to_string(),
                    author_seq: author.author_seq,
                    lamport: author.lamport,
                    version_hash: Self::row_version(file),
                    naming_device_id: naming.to_string(),
                }
            })
            .collect();
        let snapshot = RebootstrapSnapshot::new(
            group.clone(),
            files,
            vec![author.to_wire_bytes()],
            Vec::new(),
            vec![Self::witness_for(author)],
            Vec::new(),
            vec![SnapshotAuthorState {
                device_id: author.device_id.as_str().to_string(),
                watermark: author.author_seq,
                tip_change_hash: author_hash,
            }],
            path_heads,
            author.lamport,
        )
        .unwrap();
        let checkpoint = Checkpoint::new(group, vec![author_hash], snapshot.snapshot_hash());
        let mut installed_checkpoint = self.installed_checkpoint.lock().unwrap();
        let previous = installed_checkpoint.replace(checkpoint.checkpoint_hash().0);
        let manifest = SnapshotManifest::new_signed(
            checkpoint,
            Vec::new(),
            previous,
            DeviceId("device-b".to_string()),
            &SigningKey::from_bytes(&[7u8; 32]),
        )
        .unwrap();
        (manifest, snapshot.canonical_encoding())
    }

    /// Evidence that `change` was published, as a base carries it for the
    /// rows that change authored. The install stores it as it is; checking
    /// it belongs to whoever accepted the base.
    fn witness_for(
        change: &yadorilink_replica_domain::change::Change,
    ) -> yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness {
        use yadorilink_replica_domain::authorization_checkpoint::{
            build_merkle_proof, canonical_signing_bytes, checkpoint_hash, encode_merkle_proof,
            fingerprint_signing_key, merkle_root, sign_checkpoint, AuthorizationCheckpoint,
        };
        let hash = change.compute_hash();
        let author = SigningKey::from_bytes(&[13u8; 32]).verifying_key();
        let checkpoint = AuthorizationCheckpoint {
            group_id: GROUP.to_string(),
            device_id: change.device_id.as_str().to_string(),
            signing_key_fingerprint: fingerprint_signing_key(&author),
            merkle_root: merkle_root(&[hash.0]),
            leaf_count: 1,
            checkpoint_seq: 1,
            signer_key_id: [2; 32],
            policy_epoch: 0,
            policy_seq: 1,
            policy_head: [3; 32],
            issued_at_unix: 0,
        };
        let encoded = canonical_signing_bytes(&checkpoint);
        let signature = sign_checkpoint(&checkpoint, &SigningKey::from_bytes(&[42; 32]));
        yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness {
            change_hash: hash,
            checkpoint_hash: checkpoint_hash(&encoded, &signature),
            checkpoint_encoded: encoded,
            checkpoint_signature: signature.to_vec(),
            author_signing_public_key: author.to_bytes(),
            merkle_proof_encoded: encode_merkle_proof(&build_merkle_proof(&[hash.0], 0)),
        }
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

const OLD: &[u8] = b"the version this device had placed before the install\n";
const NEW: &[u8] = b"the version the installed base carries, which this device never placed\n";

/// The state an install leaves behind: the row names the installed version,
/// the disk still holds the replaced version's bytes, and nothing has
/// reconciled the two. A watcher event for those bytes is the old version,
/// not an edit, and capturing it would publish it over the installed
/// version to every peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replaced_versions_bytes_are_not_captured_as_an_edit_of_the_installed_version() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);

    let outcome = fx.event("doc.txt").await;

    assert_eq!(outcome, LocalChangeOutcome::None, "the replaced version's bytes were captured");
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(NEW)));
}

/// The same bytes, found by the startup reconciliation scan instead of a
/// watcher event -- the path a crash right after the install commits takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_startup_scan_does_not_capture_a_replaced_versions_bytes() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);

    let minted = fx.processor.scan_existing_files(GROUP, &fx.root).unwrap();

    assert!(
        minted.iter().all(|record| record.path != "doc.txt"),
        "the scan captured the replaced version: {minted:?}"
    );
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(NEW)));
}

/// A path only the installed base has is not on disk yet, because the
/// install writes nothing. Its absence is not a deletion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_startup_scan_does_not_tombstone_a_path_the_install_has_not_placed() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW), fx.snapshot_row("arrived.txt", NEW)]);

    let minted = fx.processor.scan_existing_files(GROUP, &fx.root).unwrap();

    assert!(
        minted.iter().all(|record| record.path != "arrived.txt"),
        "the scan tombstoned a path the install has not placed: {minted:?}"
    );
    assert_eq!(fx.indexed_blocks("arrived.txt"), Some(fx.blocks(NEW)));
}

/// A local edit prepared from disk before the install and committed after
/// it describes bytes whose base the install replaced. The commit is the
/// last point that can refuse it, and it must.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_edit_prepared_before_an_install_is_refused_at_commit() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    let edited: &[u8] = b"an edit of the old version, prepared before the install\n";
    let blocks = fx.blocks(edited);
    let version = FileVersion::new(
        blocks
            .iter()
            .map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size })
            .collect(),
        edited.len() as u64,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let mutation = PreparedLocalMutation::Upsert {
        record: FileRecord {
            path: "doc.txt".to_string(),
            size: edited.len() as u64,
            mtime_unix_nanos: 0,
            blocks,
            deleted: false,
        },
        op: Op::Put {
            path: SyncPath("doc.txt".to_string()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        },
        version,
        meta: None,
    };

    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);

    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[11u8; 32]));
    let committed = fx.state.file_index_repository().commit_local_mutations_batch(
        GROUP,
        &[mutation],
        &[],
        "device-a",
        yadorilink_sync_sqlite::file_index::ChangeEmissionContext {
            emitter: &emitter,
            permit: &RootCommitPermit::for_tests(),
        },
    );

    assert!(
        matches!(
            committed,
            Err(yadorilink_sync_sqlite::SyncSqliteError::PathAwaitingSnapshotInstallReconciliation {
                ..
            })
        ),
        "an edit of a replaced version was not refused as one: {committed:?}"
    );
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(NEW)));
}

// --- Reconciliation, and the crash windows inside it ---

impl Fixture {
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

    /// Whether `path` holds exactly a content-free placeholder of `size`.
    fn is_placeholder_of(&self, path: &str, size: usize) -> bool {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(self.root.join(path)).unwrap();
        metadata.is_file() && metadata.len() == size as u64 && metadata.blocks() == 0
    }
}

/// The replaced version's bytes are superseded, not an edit: reconciliation
/// removes them, places the installed version's placeholder, and preserves
/// nothing. Afterwards neither a watcher event nor the startup scan has
/// anything to author.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconciliation_replaces_a_replaced_versions_bytes_with_the_installed_placeholder() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);

    fx.repair();

    assert!(fx.is_placeholder_of("doc.txt", NEW.len()), "doc.txt still holds the old version");
    assert_eq!(fx.disk_entries(), vec!["doc.txt".to_string()], "nothing is preserved");
    assert_eq!(fx.event("doc.txt").await, LocalChangeOutcome::None);
    let minted = fx.processor.scan_existing_files(GROUP, &fx.root).unwrap();
    assert!(minted.is_empty(), "the scan authored something after reconciliation: {minted:?}");
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(NEW)));
}

/// Bytes the replaced version cannot account for -- an edit of it nobody
/// captured, made before the install or after it -- are neither discarded
/// nor authored over the installed version. They are moved aside under a
/// conflict-copy name, which the scan then captures as a file of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconciliation_preserves_an_uncaptured_edit_as_a_conflict_copy() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);
    let edit: &[u8] = b"an edit of the old version that local capture never saw\n";
    std::fs::write(fx.root.join("doc.txt"), edit).unwrap();

    fx.repair();

    assert!(fx.is_placeholder_of("doc.txt", NEW.len()));
    let entries = fx.disk_entries();
    let preserved: Vec<&String> = entries.iter().filter(|name| *name != "doc.txt").collect();
    assert_eq!(preserved.len(), 1, "the edit was not preserved exactly once: {entries:?}");
    assert_eq!(std::fs::read(fx.root.join(preserved[0])).unwrap(), edit);

    // Authored as this device authors on a group with history: through its
    // change emitter. A row minted without one names no author, which a
    // group with an installed base refuses.
    let processor = LocalChangeProcessor::new(
        fx.state.clone(),
        fx.store.clone(),
        "device-a".to_string(),
        Arc::new(RootLease::for_tests()),
    )
    .with_change_emitter(Arc::new(ChangeEmitter::new(
        "device-a",
        SigningKey::from_bytes(&[11u8; 32]),
    )));
    let minted = processor.scan_existing_files(GROUP, &fx.root).unwrap();
    assert_eq!(
        minted.iter().map(|record| record.path.as_str()).collect::<Vec<_>>(),
        vec![preserved[0].as_str()],
        "only the preserved copy may be authored, as a new file"
    );
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(NEW)));
}

/// A crash after reconciliation emptied the path (removed stale bytes or
/// moved an edit aside) but before it placed anything: the next pass finds
/// nothing there, places the installed version, and the empty path was
/// never read as a deletion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_the_path_was_emptied_is_finished_by_the_next_pass() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();

    let before_repair = fx.processor.scan_existing_files(GROUP, &fx.root).unwrap();
    assert!(before_repair.is_empty(), "an emptied held path was tombstoned: {before_repair:?}");

    fx.repair();

    assert!(fx.is_placeholder_of("doc.txt", NEW.len()));
    assert_eq!(fx.disk_entries(), vec!["doc.txt".to_string()]);
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(NEW)));
}

/// A crash after reconciliation placed the installed placeholder but
/// before it released the path: the next pass recognises its own
/// placeholder and keeps it, rather than moving it aside as something the
/// replaced version cannot account for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_the_placeholder_was_placed_does_not_preserve_it_as_an_edit() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();
    yadorilink_local_storage::create_or_defer_placeholder(
        &fx.root.join("doc.txt"),
        NEW.len() as u64,
        0,
    )
    .unwrap();

    fx.repair();

    assert!(fx.is_placeholder_of("doc.txt", NEW.len()));
    assert_eq!(fx.disk_entries(), vec!["doc.txt".to_string()], "the placeholder was preserved");
    assert!(
        fx.state.snapshot_install_hold_repository().held_paths(GROUP).unwrap().is_empty(),
        "the reconciled path is still held"
    );
    assert_eq!(fx.event("doc.txt").await, LocalChangeOutcome::None);
}

/// Once reconciled, the path is an ordinary one: an edit made after that is
/// an edit of the installed version and is captured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_after_reconciliation_is_captured() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);
    fx.repair();

    let edit: &[u8] = b"an edit made after the installed version was placed\n";
    std::fs::write(fx.root.join("doc.txt"), edit).unwrap();

    match fx.event("doc.txt").await {
        LocalChangeOutcome::FileChanged(record) => assert_eq!(record.blocks, fx.blocks(edit)),
        other => panic!("an edit of the reconciled path was not captured: {other:?}"),
    }
}

// --- A user writing to a held path while reconciliation runs ---

/// Saves `content` at `path` the way an editor does: written beside it and
/// renamed over it, so the path gets a new object rather than new bytes.
fn save_atomically(path: &std::path::Path, content: &[u8]) {
    let saved = path.with_file_name("editor-save.swp");
    std::fs::write(&saved, content).unwrap();
    std::fs::rename(&saved, path).unwrap();
}

impl Fixture {
    /// Every file directly under the root other than `path` and the root
    /// marker, with its bytes.
    fn preserved_besides(&self, path: &str) -> Vec<(String, Vec<u8>)> {
        self.disk_entries()
            .into_iter()
            .filter(|name| name != path)
            .map(|name| {
                let bytes = std::fs::read(self.root.join(&name)).unwrap();
                (name, bytes)
            })
            .collect()
    }
}

/// Reconciliation found the replaced version's bytes, so it is about to
/// remove them -- and the user saves over the path first. Whatever is at
/// the path by the time it acts is the user's save, which is not the
/// replaced version and must not be removed as if it were.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_save_landing_after_the_replaced_bytes_were_classified_is_not_removed() {
    use yadorilink_filesystem_sync::snapshot_install_reconcile::{
        set_reconcile_step_hook_for_test, ReconcileStepForTest,
    };
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);
    let save: &[u8] = b"a save made while reconciliation was hashing the old version\n";
    let mut saved = false;
    let _hook = set_reconcile_step_hook_for_test(move |step, path| {
        if step == ReconcileStepForTest::Classified && !saved {
            saved = true;
            save_atomically(path, save);
        }
    });

    fx.repair();

    assert_eq!(
        fx.preserved_besides("doc.txt").into_iter().map(|(_, bytes)| bytes).collect::<Vec<_>>(),
        vec![save.to_vec()],
        "the save was not preserved exactly once"
    );
    assert!(fx.is_placeholder_of("doc.txt", NEW.len()));
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(NEW)));
}

/// The path was found empty, so reconciliation is about to place the
/// installed version there -- and the user creates a file at the path
/// first. Placing the placeholder must not replace it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_created_before_the_placeholder_is_placed_is_not_replaced_by_it() {
    use yadorilink_filesystem_sync::snapshot_install_reconcile::{
        set_reconcile_step_hook_for_test, ReconcileStepForTest,
    };
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();
    let created: &[u8] = b"a file the user created at the emptied path\n";
    let mut wrote = false;
    let _hook = set_reconcile_step_hook_for_test(move |step, path| {
        if step == ReconcileStepForTest::PlacingPlaceholder && !wrote {
            wrote = true;
            save_atomically(path, created);
        }
    });

    fx.repair();
    fx.repair();

    assert_eq!(
        fx.preserved_besides("doc.txt").into_iter().map(|(_, bytes)| bytes).collect::<Vec<_>>(),
        vec![created.to_vec()],
        "the created file was not preserved exactly once"
    );
    assert!(fx.is_placeholder_of("doc.txt", NEW.len()));
    assert!(
        fx.state.snapshot_install_hold_repository().held_paths(GROUP).unwrap().is_empty(),
        "the path is still held after a pass found it empty again"
    );
}

/// A crash after reconciliation took the object at a held path aside to
/// examine it, but before it settled it: the next pass finds the taken
/// object and settles it first. A user's save taken that way is preserved,
/// not discarded with the reserved name it was left under.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_the_object_was_taken_aside_preserves_a_save_it_took() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);
    let save: &[u8] = b"a save the crashed pass had taken aside\n";
    let taken = yadorilink_filesystem_sync::snapshot_install_reconcile::taken_object_path_for_test(
        &fx.root, "doc.txt",
    );
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();
    std::fs::write(&taken, save).unwrap();

    fx.repair();

    assert!(!taken.exists(), "the taken object was left under its reserved name");
    assert_eq!(
        fx.preserved_besides("doc.txt").into_iter().map(|(_, bytes)| bytes).collect::<Vec<_>>(),
        vec![save.to_vec()],
        "the taken save was not preserved exactly once"
    );
    assert!(fx.is_placeholder_of("doc.txt", NEW.len()));
}

// --- What the install leaves held, and what the other writers do with it ---

/// A path whose installed row places exactly what the replaced one did has
/// nothing on disk to reconcile: it is not held, and it keeps the replaced
/// row's materialization state instead of becoming a placeholder the disk
/// does not hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_the_install_left_unchanged_is_not_held_and_keeps_its_state() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    let placed = fx.state.file_index_repository().get_file(GROUP, "doc.txt").unwrap().unwrap();
    let mut row = fx.snapshot_row("doc.txt", OLD);
    row.record.mtime_unix_nanos = placed.mtime_unix_nanos;
    row.unix_mode = fx.state.file_index_repository().get_unix_mode(GROUP, "doc.txt").unwrap();

    fx.install(vec![row]);

    assert!(
        fx.state.snapshot_install_hold_repository().held_paths(GROUP).unwrap().is_empty(),
        "a path whose placed object the install did not change was held"
    );
    assert_eq!(
        fx.state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated)
    );
}

/// A second install before the first was reconciled replaces rows that
/// were never placed. What is on disk is still what the first install's
/// replaced row placed, so the hold keeps describing that row, and
/// reconciliation recognises the bytes as superseded instead of preserving
/// them as an edit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_install_before_reconciliation_keeps_the_original_hold() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);
    let newer: &[u8] = b"a still newer base installed before the first was reconciled\n";

    fx.install(vec![fx.snapshot_row("doc.txt", newer)]);
    fx.repair();

    assert!(fx.is_placeholder_of("doc.txt", newer.len()));
    assert_eq!(fx.disk_entries(), vec!["doc.txt".to_string()], "the old version was preserved");
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(newer)));
}

/// The placeholder-identity backfill vouches for whatever regular file of
/// the indexed size it finds at a placeholder row's path. Under a held
/// path that file is the replaced row's, so the backfill must leave the
/// path alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_placeholder_identity_backfill_skips_a_held_path() {
    use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionPort;
    let fx = Fixture::new();
    let old: &[u8] = b"old bytes, exactly as long as the new\n";
    let new: &[u8] = b"new bytes, exactly as long as the old\n";
    assert_eq!(old.len(), new.len());
    fx.hydrated("doc.txt", old).await;
    fx.install(vec![fx.snapshot_row("doc.txt", new)]);

    yadorilink_filesystem_sync::materialization_repair::backfill_placeholder_generations(
        fx.state.as_ref(),
        &fx.root,
        GROUP,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();

    assert!(
        fx.state
            .list_placeholder_paths_missing_generation(GROUP)
            .unwrap()
            .contains(&"doc.txt".to_string()),
        "the backfill recorded the replaced version's file as the installed placeholder"
    );
}

/// A second install lands while a pass is reconciling the path for the
/// first: after it placed the first install's placeholder, before it
/// released the hold. The hold now stands for the second install, whose
/// row the pass never read, so the pass must not release it -- and what it
/// placed for a row that is no longer installed must not stay behind as
/// that row's projection or as a conflict copy of nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_does_not_release_a_hold_a_later_install_renewed() {
    a_later_install_lands_at(ReconcileStepForTest::PlaceholderPlaced).await;
}

/// The same, with the later install landing before the placeholder is even
/// placed: the pass records the identity of what it placed on a row that is
/// already the later install's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_does_not_vouch_for_its_placeholder_under_a_later_installs_row() {
    a_later_install_lands_at(ReconcileStepForTest::PlacingPlaceholder).await;
}

use yadorilink_filesystem_sync::snapshot_install_reconcile::ReconcileStepForTest;

async fn a_later_install_lands_at(at: ReconcileStepForTest) {
    use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionPort;
    use yadorilink_filesystem_sync::snapshot_install_reconcile::set_reconcile_step_hook_for_test;
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);
    let newer: &[u8] = b"a newer base, installed while the first was being reconciled\n";
    assert_ne!(newer.len(), NEW.len());
    let (manifest, snapshot) = fx.prepare_install(vec![fx.snapshot_row("doc.txt", newer)]);
    let state = fx.state.clone();
    let mut installed = false;
    let _hook = set_reconcile_step_hook_for_test(move |step, _| {
        if step == at && !installed {
            installed = true;
            state.install_base_for_tests(&manifest, &snapshot).unwrap();
        }
    });

    fx.repair();

    assert_eq!(
        fx.state.snapshot_install_hold_repository().held_paths(GROUP).unwrap(),
        vec!["doc.txt".to_string()],
        "a pass released the hold of an install it never read"
    );
    assert!(
        fx.state
            .list_placeholder_paths_missing_generation(GROUP)
            .unwrap()
            .contains(&"doc.txt".to_string()),
        "the identity of a placeholder for a row no longer installed was left on the newer row"
    );

    fx.repair();

    assert!(fx.is_placeholder_of("doc.txt", newer.len()));
    assert_eq!(
        fx.disk_entries(),
        vec!["doc.txt".to_string()],
        "the superseded placeholder was left behind"
    );
    assert!(fx.state.snapshot_install_hold_repository().held_paths(GROUP).unwrap().is_empty());
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(newer)));
}

/// The user saves into the installed placeholder right after the pass
/// placed it, and the watcher's flush for that save arrives while the pass
/// still holds the path. The flush must wait for the pass rather than read
/// the path as held and drop the save: once the hold is released, the save
/// is an ordinary edit of the installed version, and it is the only event
/// the save will ever produce.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_save_flushed_while_the_pass_still_holds_the_path_is_captured_after_it() {
    use yadorilink_filesystem_sync::snapshot_install_reconcile::set_reconcile_step_hook_for_test;
    let fx = Fixture::new();
    fx.hydrated("doc.txt", OLD).await;
    fx.install(vec![fx.snapshot_row("doc.txt", NEW)]);
    let flusher = Arc::new(LocalChangeProcessor::new(
        fx.state.clone(),
        fx.store.clone(),
        "device-a".to_string(),
        Arc::new(RootLease::for_tests()),
    ));
    let root = fx.root.clone();
    let save: &[u8] = b"a save into the placeholder the pass had just placed\n";
    let flushed = Arc::new(std::sync::Mutex::new(None));
    let flushed_by_hook = flushed.clone();
    let _hook = set_reconcile_step_hook_for_test(move |step, path| {
        if step != ReconcileStepForTest::PlaceholderPlaced
            || flushed_by_hook.lock().unwrap().is_some()
        {
            return;
        }
        std::fs::write(path, save).unwrap();
        let (flusher, root, path) = (flusher.clone(), root.clone(), path.to_path_buf());
        let task = tokio::runtime::Handle::current().spawn(async move {
            let event = FsChangeEvent { path, kind: FsChangeKind::CreatedOrModified };
            flusher.process_event(GROUP, &root, &event).await.unwrap()
        });
        *flushed_by_hook.lock().unwrap() = Some(task);
        // Long enough for the flush to reach the path, while the pass is
        // still on it.
        std::thread::sleep(std::time::Duration::from_millis(300));
    });

    fx.repair();
    let task = flushed.lock().unwrap().take().expect("the pass placed the placeholder");

    match task.await.unwrap() {
        LocalChangeOutcome::FileChanged(record) => assert_eq!(record.blocks, fx.blocks(save)),
        other => panic!("the save was dropped as an edit of a held path: {other:?}"),
    }
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(save)));
}

// --- Directory rows ------------------------------------------------------
//
// An installed base can carry explicit directories, and the file set it
// replaces can disagree with the one it installs about which names are
// directories. The pass places an installed directory as a real directory,
// removes one the install dropped only when it is empty (anything left in
// it is kept), and relocates a file whose name a live descendant needs as
// its directory, instead of holding the path forever on `ENOTDIR`.

impl Fixture {
    fn directory_row(&self, path: &str, unix_mode: Option<u32>) -> SnapshotFile {
        SnapshotFile {
            record: FileRecord {
                path: path.to_string(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: false,
            },
            record_kind: RecordKind::Directory,
            unix_mode,
            ..self.snapshot_row(path, b"")
        }
    }

    fn holds(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .state
            .snapshot_install_hold_repository()
            .list(GROUP)
            .unwrap()
            .into_iter()
            .map(|hold| hold.path)
            .collect();
        paths.sort();
        paths
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn installed_directory_row_settles_through_directory_lane() {
    use std::os::unix::fs::PermissionsExt as _;
    let fx = Fixture::new();
    fx.install(vec![fx.directory_row("docs", Some(0o750))]);

    fx.repair();

    let metadata = std::fs::symlink_metadata(fx.root.join("docs")).unwrap();
    assert!(metadata.is_dir(), "an installed directory must be a real directory");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o750);
    assert!(fx.holds().is_empty(), "the path must not stay held: {:?}", fx.holds());
    let minted = fx.processor.scan_existing_files(GROUP, &fx.root).unwrap();
    assert!(minted.is_empty(), "the scan authored something: {minted:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_installed_directory_over_the_replaced_files_bytes_replaces_them() {
    let fx = Fixture::new();
    fx.hydrated("docs", OLD).await;
    fx.install(vec![fx.directory_row("docs", None)]);

    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("docs")).unwrap().is_dir());
    assert_eq!(fx.disk_entries(), vec!["docs".to_string()], "the stale bytes are not preserved");
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_installed_directory_over_an_untracked_directory_keeps_what_is_in_it() {
    let fx = Fixture::new();
    std::fs::create_dir(fx.root.join("docs")).unwrap();
    std::fs::write(fx.root.join("docs/.DS_Store"), b"finder state").unwrap();
    fx.install(vec![fx.directory_row("docs", None)]);

    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("docs")).unwrap().is_dir());
    assert_eq!(std::fs::read(fx.root.join("docs/.DS_Store")).unwrap(), b"finder state");
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_the_next_install_drops_is_removed_only_when_empty() {
    let fx = Fixture::new();
    fx.install(vec![fx.directory_row("empty", None), fx.directory_row("kept", None)]);
    fx.repair();
    std::fs::write(fx.root.join("kept/notes.txt"), b"never captured").unwrap();

    fx.install(Vec::new());
    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("empty")).is_err());
    assert_eq!(std::fs::read(fx.root.join("kept/notes.txt")).unwrap(), b"never captured");
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_of_file_and_descendant_snapshot_relocates_without_enotdir_hold() {
    let fx = Fixture::new();
    let child: &[u8] = b"the descendant that needs a as its directory\n";
    fx.install(vec![fx.snapshot_row("a", NEW), fx.snapshot_row("a/x", child)]);

    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("a")).unwrap().is_dir());
    assert!(fx.is_placeholder_of("a/x", child.len()));
    let entries = fx.disk_entries();
    let relocated: Vec<&String> = entries.iter().filter(|name| *name != "a").collect();
    assert_eq!(relocated.len(), 1, "the file a must sit beside its directory: {entries:?}");
    assert!(fx.is_placeholder_of(relocated[0], NEW.len()));
    assert!(fx.holds().is_empty(), "no path may stay held on ENOTDIR: {:?}", fx.holds());
}

/// The relocation is a projection, not an edit: the file's row moves to the
/// copy name with it, so capture finds the copy already indexed and no file
/// missing at `a`, and authors nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relocated_file_is_indexed_at_its_copy_name_and_authors_nothing() {
    let fx = Fixture::new();
    let child: &[u8] = b"the descendant that needs a as its directory\n";
    fx.install(vec![fx.snapshot_row("a", NEW), fx.snapshot_row("a/x", child)]);

    fx.repair();

    let copy = fx.disk_entries().into_iter().find(|name| name != "a").expect("a copy name");
    assert_eq!(fx.indexed_blocks(&copy), Some(fx.blocks(NEW)), "the copy name holds a's row");
    assert_eq!(fx.indexed_blocks("a"), None, "no live row claims a file at a");
    let minted = fx.processor.scan_existing_files(GROUP, &fx.root).unwrap();
    assert!(minted.is_empty(), "the scan authored something: {minted:?}");
}

/// A directory the pass made only to hold installed rows goes with the
/// last of them, and only then.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_structural_directory_goes_with_the_last_installed_descendant() {
    let fx = Fixture::new();
    fx.install(vec![fx.snapshot_row("a/b/x", NEW), fx.snapshot_row("a/y", NEW)]);
    fx.repair();
    assert!(fx.is_placeholder_of("a/b/x", NEW.len()));

    fx.install(vec![fx.snapshot_row("a/y", NEW)]);
    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("a/b")).is_err(), "a/b outlived a/b/x");
    assert!(fx.is_placeholder_of("a/y", NEW.len()), "a went while a/y needs it");

    fx.install(Vec::new());
    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("a")).is_err(), "a outlived a/y");
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// An explicit directory an install drops while a live row stays below it
/// is kept for that row, as structural: it goes with the row, not before,
/// and not never.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_explicit_directory_with_a_live_row_below_goes_with_that_row() {
    let fx = Fixture::new();
    fx.install(vec![fx.directory_row("d", None), fx.snapshot_row("d/f", NEW)]);
    fx.repair();
    assert!(std::fs::symlink_metadata(fx.root.join("d")).unwrap().is_dir());

    fx.install(vec![fx.snapshot_row("d/f", NEW)]);
    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("d")).unwrap().is_dir());
    assert!(fx.is_placeholder_of("d/f", NEW.len()));

    fx.install(Vec::new());
    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("d")).is_err(), "d outlived d/f");
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// A directory the pass did not make is never removed, however empty, when
/// an install drops the rows below it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_users_directory_is_not_pruned_when_the_rows_below_it_go() {
    let fx = Fixture::new();
    std::fs::create_dir(fx.root.join("mine")).unwrap();
    fx.install(vec![fx.snapshot_row("mine/x", NEW)]);
    fx.repair();

    fx.install(Vec::new());
    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("mine")).unwrap().is_dir());
    assert!(std::fs::symlink_metadata(fx.root.join("mine/x")).is_err());
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// A pass that crashes after the last dropped row below a structural
/// directory is gone, before that directory is pruned, leaves the row held:
/// the next pass finds it gone and prunes the directory. Released first,
/// nothing would ever look at the directory again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_before_the_structural_ancestor_is_pruned_is_finished_by_the_next_pass() {
    use yadorilink_filesystem_sync::snapshot_install_reconcile::set_reconcile_step_hook_for_test;
    let fx = Fixture::new();
    fx.install(vec![fx.snapshot_row("a/x", NEW)]);
    fx.repair();
    fx.install(Vec::new());
    {
        let _hook = set_reconcile_step_hook_for_test(|step, _| {
            if step == ReconcileStepForTest::PruningAncestors {
                panic!("crash after a/x is gone, before a is pruned");
            }
        });
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fx.repair()));
        assert!(crashed.is_err());
    }
    assert!(std::fs::symlink_metadata(fx.root.join("a/x")).is_err());
    assert_eq!(fx.holds(), vec!["a/x".to_string()]);

    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("a")).is_err(), "a outlived a/x");
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// A structural directory whose lock is busy when its last dropped row goes
/// keeps that row held, and goes on the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_structural_ancestor_keeps_the_dropped_row_held_until_it_is_pruned() {
    let fx = Fixture::new();
    fx.install(vec![fx.snapshot_row("a/x", NEW)]);
    fx.repair();
    fx.install(Vec::new());

    let lock = fx.state.path_lock(GROUP, "a");
    let guard = lock.try_lock().unwrap();
    fx.repair();
    drop(guard);
    assert!(std::fs::symlink_metadata(fx.root.join("a/x")).is_err());
    assert_eq!(fx.holds(), vec!["a/x".to_string()]);

    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("a")).is_err(), "a outlived a/x");
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// The copy name the install gives a relocated file is the one the live
/// projection gives the same head: named for the head's naming device (not
/// the row's origin, which differs for content carried forward on another
/// device's behalf), and with no mtime stamp, since the live frontier
/// carries none. Otherwise a device that installed the base and one that
/// converged to it live place the same file under two names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relocated_files_copy_name_is_the_one_the_live_projection_gives_it() {
    let fx = Fixture::new();
    let child: &[u8] = b"the descendant that needs a as its directory\n";
    let mut a = fx.snapshot_row("a", NEW);
    a.record.mtime_unix_nanos = 1_700_000_000_123_456_789;
    let expected = yadorilink_replica_engine::namespace::first_copy_name(
        "a",
        &fx.frontier_head(&a, "device-original"),
    );
    let (manifest, snapshot) = fx.prepare_install_with_heads(
        vec![a, fx.snapshot_row("a/x", child)],
        &[("a", "device-original")],
    );
    fx.state.install_base_for_tests(&manifest, &snapshot).unwrap();

    fx.repair();

    assert_eq!(fx.indexed_blocks(&expected), Some(fx.blocks(NEW)), "{:?}", fx.disk_entries());
    assert!(fx.is_placeholder_of(&expected, NEW.len()), "{:?}", fx.disk_entries());
}

/// A dropped path's lock is busy for one pass, so the directory above it,
/// where an installed entry now belongs, is not empty yet. That is not
/// untracked content and not a reason to give up on the entry: the path
/// stays held, and the pass after the dropped path is gone places it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entry_waits_for_a_held_path_below_its_name_instead_of_being_dropped() {
    let fx = Fixture::new();
    fx.install(vec![fx.snapshot_row("a/x", OLD)]);
    fx.repair();
    assert!(fx.is_placeholder_of("a/x", OLD.len()));
    fx.install(vec![fx.snapshot_row("a", NEW)]);

    let lock = fx.state.path_lock(GROUP, "a/x");
    let guard = lock.try_lock().unwrap();
    fx.repair();
    drop(guard);

    assert_eq!(fx.holds(), vec!["a".to_string(), "a/x".to_string()], "a was released unplaced");
    fx.repair();
    assert!(fx.is_placeholder_of("a", NEW.len()), "{:?}", fx.disk_entries());
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// A directory of the user's holds the name an installed entry needs. It
/// is kept, with what is in it, and the entry goes to its copy name, in the
/// index and on disk, as the live projection places it: the index never
/// names a file where the disk has a directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_installed_entry_over_a_users_directory_goes_to_its_copy_name() {
    let fx = Fixture::new();
    std::fs::create_dir(fx.root.join("a")).unwrap();
    std::fs::write(fx.root.join("a/mine"), b"the user's own").unwrap();
    let a = fx.snapshot_row("a", NEW);
    let expected = yadorilink_replica_engine::namespace::first_copy_name(
        "a",
        &fx.frontier_head(&a, "device-original"),
    );
    let (manifest, snapshot) = fx.prepare_install_with_heads(vec![a], &[("a", "device-original")]);
    fx.state.install_base_for_tests(&manifest, &snapshot).unwrap();

    fx.repair();
    fx.repair();

    assert_eq!(std::fs::read(fx.root.join("a/mine")).unwrap(), b"the user's own");
    assert_eq!(fx.indexed_blocks("a"), None, "the index names a file where a directory is");
    assert_eq!(fx.indexed_blocks(&expected), Some(fx.blocks(NEW)));
    assert!(fx.is_placeholder_of(&expected, NEW.len()), "{:?}", fx.disk_entries());
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// A dropped explicit directory is not empty only because the dropped row
/// below it could not be reconciled in this pass. That is not untracked
/// content: the directory stays held, and goes with the row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_directory_waits_for_a_held_path_below_it_instead_of_being_retained() {
    let fx = Fixture::new();
    fx.install(vec![fx.directory_row("d", None), fx.snapshot_row("d/f", NEW)]);
    fx.repair();
    fx.install(Vec::new());

    let lock = fx.state.path_lock(GROUP, "d/f");
    let guard = lock.try_lock().unwrap();
    fx.repair();
    drop(guard);
    assert_eq!(fx.holds(), vec!["d".to_string(), "d/f".to_string()]);

    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("d")).is_err(), "d outlived d/f");
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// A pass that crashes after making an installed directory and before
/// committing its proof is finished by the next one, which finds the
/// directory already there and settles it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_that_crashed_after_making_an_installed_directory_is_finished_by_the_next() {
    use yadorilink_filesystem_sync::snapshot_install_reconcile::set_reconcile_step_hook_for_test;
    let fx = Fixture::new();
    fx.install(vec![fx.directory_row("d", Some(0o750))]);
    {
        let _hook = set_reconcile_step_hook_for_test(|step, _| {
            if step == ReconcileStepForTest::DirectoryPlaced {
                panic!("crash after the directory, before its proof");
            }
        });
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fx.repair()));
        assert!(crashed.is_err());
    }
    assert!(std::fs::symlink_metadata(fx.root.join("d")).unwrap().is_dir());
    assert_eq!(fx.holds(), vec!["d".to_string()]);

    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("d")).unwrap().is_dir());
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// An install that renews a directory's hold while the pass is placing it
/// makes what the pass placed a projection of a row no longer installed:
/// the pass withdraws the directory it made while it is still empty, and
/// the hold stays for the next pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_withdraws_the_directory_it_made_for_a_row_a_later_install_dropped() {
    use yadorilink_filesystem_sync::snapshot_install_reconcile::set_reconcile_step_hook_for_test;
    let fx = Fixture::new();
    fx.install(vec![fx.directory_row("d", None)]);
    let (manifest, snapshot) = fx.prepare_install(Vec::new());
    let state = fx.state.clone();
    let mut installed = false;
    let _hook = set_reconcile_step_hook_for_test(move |step, _| {
        if step == ReconcileStepForTest::DirectoryPlaced && !installed {
            installed = true;
            state.install_base_for_tests(&manifest, &snapshot).unwrap();
        }
    });

    fx.repair();

    assert!(std::fs::symlink_metadata(fx.root.join("d")).is_err(), "d was left for a dropped row");
    assert_eq!(fx.holds(), vec!["d".to_string()]);
    fx.repair();
    assert!(fx.holds().is_empty(), "{:?}", fx.holds());
}

/// DIR-1 on the snapshot-install path: a base sealed over File `a` racing
/// an explicit Directory `a` carries the Directory's row at `a` and the
/// file's at its copy name (see the seal's own DIR-1 test for how the
/// rows are chosen, in either rank order). Installing it -- with `a/x` in
/// the same base, or arriving in a later one, and over a joiner that had
/// its own `a` file placed first or had nothing -- puts the directory at
/// `a`, the file beside it, and never a directory at a copy name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_installed_directory_keeps_its_name_and_the_file_sits_beside_it() {
    let child: &[u8] = b"the descendant inside the directory\n";
    for descendant_in_the_same_base in [true, false] {
        for joiner_had_the_file in [false, true] {
            let label = format!(
                "a/x in the same base: {descendant_in_the_same_base}, \
                 joiner had a: {joiner_had_the_file}"
            );
            let fx = Fixture::new();
            if joiner_had_the_file {
                fx.hydrated("a", OLD).await;
            }
            let copy = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
                "a",
                "device-b",
                0,
                &[0xA1; 32],
            );
            let mut rows = vec![fx.directory_row("a", Some(0o755)), fx.snapshot_row(&copy, NEW)];
            if descendant_in_the_same_base {
                rows.push(fx.snapshot_row("a/x", child));
            }
            fx.install(rows.clone());
            fx.repair();
            if !descendant_in_the_same_base {
                rows.push(fx.snapshot_row("a/x", child));
                fx.install(rows);
                fx.repair();
            }

            assert!(
                std::fs::symlink_metadata(fx.root.join("a")).unwrap().is_dir(),
                "{label}: {:?}",
                fx.disk_entries()
            );
            assert!(fx.is_placeholder_of("a/x", child.len()), "{label}");
            assert!(fx.is_placeholder_of(&copy, NEW.len()), "{label}: {:?}", fx.disk_entries());
            let directories: Vec<String> = fx
                .disk_entries()
                .into_iter()
                .filter(|name| std::fs::symlink_metadata(fx.root.join(name)).unwrap().is_dir())
                .collect();
            assert_eq!(directories, vec!["a".to_string()], "{label}");
            assert_eq!(fx.disk_entries().len(), 2, "{label}: {:?}", fx.disk_entries());
            assert!(fx.holds().is_empty(), "{label}: {:?}", fx.holds());
        }
    }
}

impl Fixture {
    fn symlink_row(&self, path: &str, target: &str) -> SnapshotFile {
        SnapshotFile {
            record: FileRecord {
                path: path.to_string(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: false,
            },
            record_kind: RecordKind::Symlink,
            symlink_target: Some(target.as_bytes().to_vec()),
            ..self.snapshot_row(path, b"")
        }
    }
}

/// DIR-1 on the snapshot-install path, Symlink leaf: the base carries the
/// Directory's row at `a` and the symlink's at its copy name. Installing
/// it -- with `a/x` in the same base or a later one -- puts the directory
/// at `a` with `a/x` in it, indexes the symlink at its copy name, and
/// writes nothing at `a` or the copy name but the directory. The install
/// pass leaves every installed symlink row `Placeholder` (a symlink has no
/// content-free placeholder; it is written when materialized, as it is
/// with no directory in play), so what this pins is that the symlink's row
/// sits at its copy name and nothing -- least of all a directory -- takes
/// that name or displaces `a`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_installed_directory_keeps_its_name_and_the_symlink_sits_beside_it() {
    let child: &[u8] = b"the descendant inside the directory\n";
    for descendant_in_the_same_base in [true, false] {
        let label = format!("a/x in the same base: {descendant_in_the_same_base}");
        let fx = Fixture::new();
        let copy = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "a",
            "device-b",
            0,
            &[0xA2; 32],
        );
        let mut rows =
            vec![fx.directory_row("a", Some(0o755)), fx.symlink_row(&copy, "the-target")];
        if descendant_in_the_same_base {
            rows.push(fx.snapshot_row("a/x", child));
        }
        fx.install(rows.clone());
        fx.repair();
        if !descendant_in_the_same_base {
            rows.push(fx.snapshot_row("a/x", child));
            fx.install(rows);
            fx.repair();
        }

        assert!(
            std::fs::symlink_metadata(fx.root.join("a")).unwrap().is_dir(),
            "{label}: {:?}",
            fx.disk_entries()
        );
        assert!(fx.is_placeholder_of("a/x", child.len()), "{label}");
        assert!(
            fx.state.file_index_repository().get_file(GROUP, &copy).unwrap().is_some(),
            "{label}: the symlink's row at {copy}"
        );
        assert_eq!(
            fx.state
                .materialization_state_repository()
                .get_materialization_state(GROUP, &copy)
                .unwrap(),
            Some(MaterializationState::Placeholder),
            "{label}"
        );
        assert!(
            std::fs::symlink_metadata(fx.root.join(&copy)).is_err(),
            "{label}: nothing but the symlink may take {copy}"
        );
        let directories: Vec<String> = fx
            .disk_entries()
            .into_iter()
            .filter(|name| std::fs::symlink_metadata(fx.root.join(name)).unwrap().is_dir())
            .collect();
        assert_eq!(directories, vec!["a".to_string()], "{label}");
        assert_eq!(fx.disk_entries(), vec!["a".to_string()], "{label}");
        assert!(fx.holds().is_empty(), "{label}: {:?}", fx.holds());
    }
}

// --- Write-through after an install ---
//
// An installed File `a` with a live `a/x` sits at its copy name, the row
// moved there. The copy name is the projection's; a user's delete or edit
// of it is an operation on `a`, authored as `Delete(a)` / `Put(a)`.

impl Fixture {
    /// A processor over the same replica that signs what it captures.
    fn authoring_processor(&self) -> LocalChangeProcessor {
        LocalChangeProcessor::new(
            self.state.clone(),
            self.store.clone(),
            "device-a".to_string(),
            Arc::new(RootLease::for_tests()),
        )
        .with_change_emitter(Arc::new(ChangeEmitter::new(
            "device-a",
            SigningKey::from_bytes(&[21u8; 32]),
        )))
    }

    /// Every op this replica's own device authored.
    fn own_ops(&self) -> Vec<Op> {
        self.state
            .change_history_repository()
            .dag_list_group_changes(GROUP)
            .unwrap()
            .into_iter()
            .filter(|change| change.device_id.as_str() == "device-a")
            .flat_map(|change| change.ops)
            .collect()
    }

    /// Installs `a` (a File) and `a/x`, with the base's head for `a`, and
    /// reconciles: `a` is a directory and the file sits at its copy name.
    fn installed_relocated_file(&self) -> String {
        let child: &[u8] = b"the descendant that needs a as its directory\n";
        let (manifest, snapshot) = self.prepare_install_with_heads(
            vec![self.snapshot_row("a", NEW), self.snapshot_row("a/x", child)],
            &[("a", "device-b"), ("a/x", "device-b")],
        );
        self.state.install_base_for_tests(&manifest, &snapshot).unwrap();
        self.repair();
        let copy = self.disk_entries().into_iter().find(|name| name != "a").expect("a copy name");
        assert_eq!(self.indexed_blocks(&copy), Some(self.blocks(NEW)));
        copy
    }

    async fn authored_event(&self, processor: &LocalChangeProcessor, path: &str) {
        processor
            .process_event(
                GROUP,
                &self.root,
                &FsChangeEvent {
                    path: self.root.join(path),
                    kind: FsChangeKind::CreatedOrModified,
                },
            )
            .await
            .unwrap();
    }
}

fn op_path(op: &Op) -> &str {
    match op {
        Op::Put { path, .. } | Op::Delete { path } => path.as_str(),
        Op::Move { to, .. } => to.as_str(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_an_installed_relocated_copy_deletes_the_original_entry() {
    let fx = Fixture::new();
    let copy = fx.installed_relocated_file();
    let processor = fx.authoring_processor();

    std::fs::remove_file(fx.root.join(&copy)).unwrap();
    fx.authored_event(&processor, &copy).await;

    let ops = fx.own_ops();
    assert_eq!(ops.iter().map(op_path).collect::<Vec<_>>(), vec!["a"], "{ops:?}");
    assert!(matches!(ops[0], Op::Delete { .. }), "{ops:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn editing_an_installed_relocated_copy_writes_through() {
    let fx = Fixture::new();
    let copy = fx.installed_relocated_file();
    let processor = fx.authoring_processor();

    let edit: &[u8] = b"an edit of the relocated file, through its copy name\n";
    std::fs::write(fx.root.join(&copy), edit).unwrap();
    fx.authored_event(&processor, &copy).await;

    let ops = fx.own_ops();
    assert_eq!(ops.iter().map(op_path).collect::<Vec<_>>(), vec!["a"], "{ops:?}");
    assert!(matches!(ops[0], Op::Put { origin: PutOrigin::Direct, .. }), "{ops:?}");
    assert_eq!(fx.indexed_blocks(&copy), Some(fx.blocks(edit)), "the row stays at the copy name");
}

/// The install's other shape: the base carries the copy as a row of its
/// own (a conflict copy some change authored, beside an explicit
/// Directory). Deleting it deletes it at its own name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_an_installed_authored_copy_deletes_the_copy_itself() {
    let fx = Fixture::new();
    let copy = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
        "a",
        "device-b",
        0,
        &[0xA1; 32],
    );
    let child: &[u8] = b"the descendant inside the directory\n";
    let (manifest, snapshot) = fx.prepare_install_with_heads(
        vec![
            fx.directory_row("a", Some(0o755)),
            fx.snapshot_row(&copy, NEW),
            fx.snapshot_row("a/x", child),
        ],
        &[("a", "device-b"), (&copy, "device-b"), ("a/x", "device-b")],
    );
    fx.state.install_base_for_tests(&manifest, &snapshot).unwrap();
    fx.repair();
    assert!(fx.is_placeholder_of(&copy, NEW.len()), "{:?}", fx.disk_entries());
    let processor = fx.authoring_processor();

    std::fs::remove_file(fx.root.join(&copy)).unwrap();
    fx.authored_event(&processor, &copy).await;

    let ops = fx.own_ops();
    assert_eq!(ops.iter().map(op_path).collect::<Vec<_>>(), vec![copy.as_str()], "{ops:?}");
    assert!(matches!(ops[0], Op::Delete { .. }), "{ops:?}");
}
