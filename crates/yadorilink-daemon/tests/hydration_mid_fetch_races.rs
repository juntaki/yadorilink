//! What hydration does when the world moves under it mid-fetch.
//!
//! Fetching a placeholder's content takes as long as the transfer takes, and
//! two things can change during that window that make the attempt's own
//! captured state stale:
//!
//! ```text
//!   local    an editor writes real content into the placeholder's file.
//!            The index row is untouched — only the bytes on disk moved —
//!            so nothing about DAG identity can detect this.
//!
//!   remote   a newer version supersedes the row. The attempt is still
//!            holding the OLD record; committing it would write the old
//!            bytes and then mark the NEW version `Hydrated`, leaving the
//!            index claiming a version disk does not hold.
//!
//!   both     the attempt must fail rather than commit. Failing costs a
//!            retry; committing loses an edit or lies about what is on disk.
//! ```
//!
//! The supersession case is asserted on the index, not on the bytes. A
//! supersession can land after the pre-write identity re-check and before the
//! commit — that window is narrow but real, and both hydration paths document
//! it — so the old version's bytes reaching disk is a legal outcome. What is
//! never legal is the row claiming `Hydrated` for a version this attempt did
//! not write; the next attempt rewrites disk from the row that actually won.
//!
//! ```text
//! ```
//!
//! A local edit is injected from inside the on-demand device's block store,
//! at an exact point of the attempt: when the first fetched block is stored
//! (mid-fetch), or when the first block is read back to assemble the file
//! (after the commit decision, before the rename that publishes it). Timing
//! it against the transfer instead -- wait for `Hydrating`, then write --
//! stops landing mid-fetch once the fetch is faster than the poll, and the
//! edit then races the assemble instead of the fetch. The supersession case
//! is still synchronized on the row reaching `Hydrating`: its outcome is
//! asserted on the index and holds wherever in the attempt it lands.

mod support;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use support::wait_until_with_context;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::hydration;
use yadorilink_local_storage::{
    BlockStore, ContentHash, GcReport, LocallyHashedBlock, SegmentBlockStore, StorageError,
};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

const GROUP: &str = "hydration-race-group";
const PATH: &str = "bigfile.bin";

/// When [`EditingBlockStore`] performs its one armed edit.
enum EditPoint {
    /// Before the first block this device stores -- in a hydration, the
    /// first block its fetch brings in.
    FirstBlockStored,
    /// Before the first read of this block -- in a hydration whose blocks
    /// were all missing, the assemble of the file after the commit decision.
    FirstReadOf(String),
}

struct ArmedEdit {
    at: EditPoint,
    path: PathBuf,
    bytes: Vec<u8>,
}

/// A real `SegmentBlockStore` that can write one local edit into the synced
/// file, exactly the way an editor would (a plain `fs::write`, no lock, no
/// index interaction), at a chosen point of the store's own use.
struct EditingBlockStore {
    inner: Arc<SegmentBlockStore>,
    armed: Mutex<Option<ArmedEdit>>,
    fired: std::sync::atomic::AtomicBool,
}

impl EditingBlockStore {
    fn arm(&self, at: EditPoint, path: PathBuf, bytes: &[u8]) {
        *self.armed.lock().unwrap() = Some(ArmedEdit { at, path, bytes: bytes.to_vec() });
    }

    fn fired(&self) -> bool {
        self.fired.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn maybe_edit(&self, matches: impl FnOnce(&EditPoint) -> bool) {
        let mut armed = self.armed.lock().unwrap();
        if armed.as_ref().is_some_and(|edit| matches(&edit.at)) {
            let edit = armed.take().unwrap();
            std::fs::write(&edit.path, &edit.bytes).unwrap();
            self.fired.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn on_store(&self) {
        self.maybe_edit(|at| matches!(at, EditPoint::FirstBlockStored));
    }
}

impl BlockStore for EditingBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.on_store();
        self.inner.put(data)
    }

    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        self.on_store();
        self.inner.put_prepared(prepared)
    }

    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        self.on_store();
        self.inner.put_prepared_batch(prepared)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.maybe_edit(|at| matches!(at, EditPoint::FirstReadOf(h) if h == hash));
        self.inner.get(hash)
    }

    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.maybe_edit(|at| matches!(at, EditPoint::FirstReadOf(h) if h == hash));
        self.inner.get_unchecked(hash)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError> {
        self.inner.delete(hash)
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        self.inner.exists(hash)
    }

    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        self.inner.list_by_prefix(prefix)
    }

    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        self.inner.present_blocks(hashes)
    }

    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.inner.sweep(live, grace_cutoff, dry_run)
    }
}

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    store: Arc<EditingBlockStore>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

impl TestDevice {
    fn path(&self, relative: &str) -> std::path::PathBuf {
        self.root.path().join(relative)
    }

    fn materialization_state(&self, path: &str) -> Option<MaterializationState> {
        self.state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, path)
            .ok()
            .flatten()
    }

    fn indexed_size(&self, path: &str) -> Option<u64> {
        self.state
            .replica_coordinator
            .file_index_repository()
            .get_file(GROUP, path)
            .ok()
            .flatten()
            .map(|record| record.size)
    }

    fn authoring_change_hash(&self, path: &str) -> Option<ChangeHash> {
        self.state
            .replica_coordinator
            .file_index_repository()
            .get_authoring_change_hash(GROUP, path)
            .ok()
            .flatten()
    }
}

fn setup_device(name: &str) -> TestDevice {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(EditingBlockStore {
        inner: Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap()),
        armed: Mutex::new(None),
        fired: std::sync::atomic::AtomicBool::new(false),
    });
    let (sync_state, index_dir) = support::open_file_backed_replica_coordinator();
    let state = DaemonState::new(name.to_string(), Arc::new(sync_state), store.clone());
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id: name.to_string(),
        state,
        store,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

/// See `ondemand_adoption.rs`'s own copy of this: an on-demand link refuses
/// to start without a connected placeholder provider, the override is
/// thread-local, and `start` runs on the test's own thread.
fn placeholder_provider_present() -> yadorilink_filesystem_sync::placeholder_backend::OverrideForTest
{
    yadorilink_filesystem_sync::placeholder_backend::OverrideForTest::enable()
}

fn start_watching(device: &TestDevice, policy: MaterializationPolicy) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.set_test_placeholder_pipeline_connected(true);
    device.state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    device
        .state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(&local_path, policy)
        .unwrap();
    LinkRuntimeController::new(device.state.clone()).start(local_path, GROUP.to_string()).unwrap();
}

async fn pair(a: &TestDevice, b: &TestDevice) {
    support::connect_two_daemons(
        &a.state,
        &a.device_id,
        &b.state,
        &b.device_id,
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;
}

/// Publishes a file big enough that its fetch is not instantaneous, and waits
/// for the on-demand peer to adopt it as a placeholder.
///
/// Adopted at its full size, not merely adopted: the author's watcher can
/// capture the file while `fs::write` is still filling it, and a peer that
/// adopted that partial version first has its row superseded again when the
/// complete one arrives -- mid-hydration, if the test has already started.
async fn publish_and_adopt(author: &TestDevice, adopter: &TestDevice, content: &[u8]) {
    std::fs::write(author.path(PATH), content).unwrap();
    wait_until_with_context(
        || {
            adopter.materialization_state(PATH) == Some(MaterializationState::Placeholder)
                && adopter.indexed_size(PATH) == Some(content.len() as u64)
        },
        Duration::from_secs(60),
        || {
            format!(
                "the on-demand peer never adopted the complete file: state={:?} size={:?}",
                adopter.materialization_state(PATH),
                adopter.indexed_size(PATH)
            )
        },
    )
    .await;
}

/// Runs hydration attempts until one assembles the file, with a local edit
/// written into it at the first read of the assemble, and returns that
/// attempt's result.
async fn hydrate_with_an_edit_during_the_assemble(
    device: &TestDevice,
    edit: &[u8],
) -> Result<(), yadorilink_daemon::sync_error::SyncError> {
    let record = device
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, PATH)
        .unwrap()
        .expect("the placeholder must be indexed");
    let first_block = hex::encode(&record.blocks.first().expect("a non-empty file").hash);
    assert!(
        !device.state.block_store.exists(&first_block).unwrap(),
        "the block must still be missing, so the only read of it is the assemble"
    );

    let mut result = Ok(());
    for _ in 0..20 {
        device.store.arm(EditPoint::FirstReadOf(first_block.clone()), device.path(PATH), edit);
        result = hydration::hydrate(&device.state, GROUP, PATH).await;
        if device.store.fired() {
            break;
        }
        // Refused before it assembled anything, so nothing raced it --
        // typically the adopter's own watcher still reporting the
        // placeholder it just wrote, which leaves the path dirty for a
        // moment. Drop what the fetch brought in, so the next attempt's
        // first read of the block is again its assemble, and go again.
        assert!(
            result.is_err(),
            "an attempt that never assembled the file reported success: {result:?}"
        );
        for block in &record.blocks {
            device.state.block_store.delete(&hex::encode(&block.hash)).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    result
}

/// An editor writing into the placeholder mid-fetch is not overwritten.
///
/// Two independent guards cover this — the path is marked dirty once the
/// watcher sees the write, and the pre-commit disk fingerprint no longer
/// matches what the attempt captured — so this is stated on the outcome
/// rather than on either one. Disabling one leaves it green; disabling both
/// makes hydration commit over the edit and report `Hydrated`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_edit_during_a_fetch_is_never_overwritten() {
    let _provider = placeholder_provider_present();
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let content = vec![0x77u8; 8_000_000];
    publish_and_adopt(&device_a, &device_b, &content).await;

    let edit = b"an edit the index has not heard about yet";
    device_b.store.arm(EditPoint::FirstBlockStored, device_b.path(PATH), edit);

    let result = hydration::hydrate(&device_b.state, GROUP, PATH).await;

    assert!(device_b.store.fired(), "the fetch never stored a block, so nothing raced it");
    assert!(
        result.is_err(),
        "hydration must fail on a mid-fetch local edit rather than overwrite it: {result:?}"
    );
    assert_eq!(
        std::fs::read(device_b.path(PATH)).unwrap(),
        edit,
        "the local edit was overwritten by the hydration it raced"
    );
}

/// An editor writing into the placeholder after the fetch, while the fetched
/// content is being assembled, is not overwritten either.
///
/// The commit decision that compares disk against the attempt's baseline
/// runs once every block is local, but assembling the file -- reading every
/// block back, writing and fsyncing a temp copy -- takes time proportional to
/// its size, and the rename that follows replaces whatever the file became
/// meanwhile. The guards have to be asked again after the assemble, right
/// before the rename, or an edit landing in that window is silently lost
/// under a row reporting `Hydrated`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_edit_while_the_file_is_assembled_is_never_overwritten() {
    let _provider = placeholder_provider_present();
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let content = vec![0x77u8; 8_000_000];
    publish_and_adopt(&device_a, &device_b, &content).await;

    let edit = b"an edit the index has not heard about yet";
    let result = hydrate_with_an_edit_during_the_assemble(&device_b, edit).await;

    assert!(device_b.store.fired(), "the file was never assembled, so nothing raced it");
    assert!(
        result.is_err(),
        "hydration must fail on a local edit made while it assembled the file: {result:?}"
    );
    assert_eq!(
        std::fs::read(device_b.path(PATH)).unwrap(),
        edit,
        "the local edit was overwritten by the rename that published the assembled file"
    );
    assert_ne!(
        device_b.materialization_state(PATH),
        Some(MaterializationState::Hydrated),
        "the row claims Hydrated for content the attempt never published"
    );
}

/// A refused attempt leaves the edit protected from the very next attempt,
/// not only from itself.
///
/// Refusing drops the attempt's guard, which puts the row back to
/// `Placeholder`, and a new attempt takes the file as it is NOW as its
/// baseline -- which is the edit. If nothing durable says the path holds an
/// uncaptured edit, an attempt started before the watcher journals it finds
/// its own baseline unchanged and renames the remote content over the edit.
/// So the retry here is made immediately, with the fetched blocks already
/// local so it goes straight to the commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_right_after_a_refused_assemble_does_not_overwrite_the_edit() {
    let _provider = placeholder_provider_present();
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let content = vec![0x77u8; 8_000_000];
    publish_and_adopt(&device_a, &device_b, &content).await;

    let edit = b"an edit the index has not heard about yet";
    let refused = hydrate_with_an_edit_during_the_assemble(&device_b, edit).await;
    assert!(device_b.store.fired(), "the file was never assembled, so nothing raced it");
    assert!(refused.is_err(), "the attempt the edit raced must be refused: {refused:?}");

    let retried = hydration::hydrate(&device_b.state, GROUP, PATH).await;

    let on_disk = std::fs::read(device_b.path(PATH)).unwrap();
    assert!(
        on_disk == edit,
        "the retry took the edit as its baseline and overwrote it ({} bytes on disk): \
         {retried:?}",
        on_disk.len()
    );
    assert_ne!(
        device_b.materialization_state(PATH),
        Some(MaterializationState::Hydrated),
        "the row claims Hydrated over a local edit"
    );
}

/// The same, for an edit that lands mid-fetch and is refused at the commit
/// decision rather than after the assemble.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_right_after_a_refused_fetch_does_not_overwrite_the_edit() {
    let _provider = placeholder_provider_present();
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let content = vec![0x77u8; 8_000_000];
    publish_and_adopt(&device_a, &device_b, &content).await;

    let edit = b"an edit the index has not heard about yet";
    device_b.store.arm(EditPoint::FirstBlockStored, device_b.path(PATH), edit);
    let refused = hydration::hydrate(&device_b.state, GROUP, PATH).await;
    assert!(device_b.store.fired(), "the fetch never stored a block, so nothing raced it");
    assert!(refused.is_err(), "the attempt the edit raced must be refused: {refused:?}");

    let retried = hydration::hydrate(&device_b.state, GROUP, PATH).await;

    let on_disk = std::fs::read(device_b.path(PATH)).unwrap();
    assert!(
        on_disk == edit,
        "the retry took the edit as its baseline and overwrote it ({} bytes on disk): \
         {retried:?}",
        on_disk.len()
    );
    assert_ne!(
        device_b.materialization_state(PATH),
        Some(MaterializationState::Hydrated),
        "the row claims Hydrated over a local edit"
    );
}

/// A newer version landing mid-fetch is not reported as hydrated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_superseded_during_a_fetch_is_never_reported_hydrated() {
    let _provider = placeholder_provider_present();
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let content = vec![0x77u8; 8_000_000];
    publish_and_adopt(&device_a, &device_b, &content).await;

    // A second real file, synced the same way, purely to obtain an authoring
    // hash that is genuinely admitted on this device — a `current` row's
    // authoring hash has to reference an admitted Change, so a fabricated
    // one would be rejected for a reason that has nothing to do with the
    // race. Which real Change it is does not matter; only that it differs.
    std::fs::write(device_a.path("marker.txt"), b"unrelated").unwrap();
    wait_until_with_context(
        || device_b.authoring_change_hash("marker.txt").is_some(),
        Duration::from_secs(60),
        || "the unrelated file never reached the on-demand peer".into(),
    )
    .await;
    let superseding = device_b.authoring_change_hash("marker.txt").expect("just waited for it");
    let original = device_b.authoring_change_hash(PATH).expect("the placeholder must be authored");
    assert_ne!(superseding, original, "the two files must have distinct authoring identities");

    let hydrating = device_b.state.clone();
    let hydrate = tokio::spawn(async move { hydration::hydrate(&hydrating, GROUP, PATH).await });

    wait_until_with_context(
        || device_b.materialization_state(PATH) == Some(MaterializationState::Hydrating),
        Duration::from_secs(30),
        || "the hydration attempt never started".into(),
    )
    .await;
    // What a peer's newer version landing on this row would do to it.
    device_b
        .state
        .replica_coordinator
        .file_index_repository()
        .set_authoring_change_hash(GROUP, PATH, &superseding)
        .unwrap();

    let result = hydrate.await.unwrap();

    assert!(
        result.is_err(),
        "hydration must fail once its row has been superseded, rather than report a version it \
         never materialized: {result:?}"
    );
    assert_ne!(
        device_b.materialization_state(PATH),
        Some(MaterializationState::Hydrated),
        "the row was marked hydrated for a version this attempt never materialized"
    );
    assert_eq!(
        device_b.authoring_change_hash(PATH),
        Some(superseding),
        "the superseding identity must survive the attempt it interrupted"
    );
}
