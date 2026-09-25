//! What an on-demand folder does when a peer publishes a file.
//!
//! On-demand is a promise about *bytes*: the folder tracks every path and
//! version its peers publish, and fetches content only when something asks
//! for it. Two ways to break that promise, neither of which any surviving
//! test states after the Change protocol's own were retired:
//!
//! ```text
//!   adoption   a new file must be adopted as a placeholder, with no blocks
//!              pulled — otherwise on-demand is eager with extra steps
//!
//!   re-offer   hearing about a version already held must not start a fetch —
//!              otherwise every reconnect hydrates the whole folder
//!
//!   pin        a pinned path IS something asking, so it must still fetch —
//!              otherwise "on-demand does not fetch" has swallowed the one
//!              request the folder exists to serve
//! ```
//!
//! All three are asserted on the index and the block store rather than on the
//! file: an on-demand placeholder legitimately exists on disk, so the file's
//! presence says nothing about whether its content was fetched.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::wait_until_with_context;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

const GROUP: &str = "ondemand-adoption-group";
const PATH: &str = "payload.bin";

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    store: Arc<SegmentBlockStore>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

impl TestDevice {
    fn path(&self, relative: &str) -> std::path::PathBuf {
        self.root.path().join(relative)
    }

    fn record(&self, path: &str) -> Option<yadorilink_replica_domain::file::FileRecord> {
        self.state.replica_coordinator.file_index_repository().get_file(GROUP, path).ok().flatten()
    }

    fn materialization_state(&self, path: &str) -> Option<MaterializationState> {
        self.state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, path)
            .ok()
            .flatten()
    }

    /// How many of `record`'s blocks this device actually holds bytes for.
    ///
    /// The observable that separates "adopted" from "fetched": an index row
    /// costs nothing, block bytes are the transfer.
    fn blocks_held(&self, record: &yadorilink_replica_domain::file::FileRecord) -> usize {
        record
            .blocks
            .iter()
            .filter(|block| self.store.get(&hex::encode(&block.hash)).is_ok())
            .count()
    }
}

fn setup_device(name: &str) -> TestDevice {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
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

/// Declares a placeholder provider present for the calling thread.
///
/// An on-demand link refuses to start unless one is connected, which in a
/// real build is a platform filesystem extension. These tests are about what
/// the sync path fetches, not about the extension. The override is
/// thread-local and `LinkRuntimeController::start` runs synchronously on the
/// test's own thread, so the guard has to outlive every `start_watching`
/// call in a test — hence returning it rather than dropping it here.
fn placeholder_provider_present() -> yadorilink_filesystem_sync::placeholder_backend::OverrideForTest
{
    yadorilink_filesystem_sync::placeholder_backend::OverrideForTest::enable()
}

/// Registers the link with `policy` and starts watching.
///
/// The policy is set between `add_link` and `start` on purpose: an on-demand
/// folder that spends its first moments eager would fetch exactly the content
/// these tests say it must not.
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

/// An on-demand folder adopts a peer's new file without fetching its blocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ondemand_folder_adopts_a_peers_file_without_fetching_its_blocks() {
    let _provider = placeholder_provider_present();
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let content = vec![0x31u8; 256 * 1024];
    std::fs::write(device_a.path(PATH), &content).unwrap();

    wait_until_with_context(
        || device_b.record(PATH).is_some(),
        Duration::from_secs(30),
        || "the on-demand folder never adopted the peer's file".into(),
    )
    .await;

    let record = device_b.record(PATH).expect("just waited for it");
    assert!(!record.blocks.is_empty(), "the adopted record must name the content it stands for");
    assert_eq!(
        device_b.materialization_state(PATH),
        Some(MaterializationState::Placeholder),
        "an on-demand adoption must land as a placeholder"
    );
    assert_eq!(
        device_b.blocks_held(&record),
        0,
        "an on-demand adoption fetched block bytes it was not asked for"
    );
}

/// Being told again about a version already held does not start a fetch.
///
/// A peer re-offers its heads on every reconnect and after every unrelated
/// local commit. If an offer for a version the placeholder already names were
/// treated as a reason to hydrate, an on-demand folder would fill up by
/// reconnecting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn re_offering_a_version_already_held_does_not_hydrate_a_placeholder() {
    let _provider = placeholder_provider_present();
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let content = vec![0x32u8; 256 * 1024];
    std::fs::write(device_a.path(PATH), &content).unwrap();
    wait_until_with_context(
        || device_b.record(PATH).is_some(),
        Duration::from_secs(30),
        || "the on-demand folder never adopted the peer's file".into(),
    )
    .await;
    let adopted = device_b.record(PATH).expect("just waited for it");

    // An unrelated commit on the peer, so a fresh round of reconciliation
    // runs and `PATH`'s unchanged version is offered again alongside it.
    std::fs::write(device_a.path("unrelated.txt"), b"noise").unwrap();
    wait_until_with_context(
        || device_b.record("unrelated.txt").is_some(),
        Duration::from_secs(30),
        || "the unrelated commit never reached the on-demand folder".into(),
    )
    .await;

    let after = device_b.record(PATH).expect("the placeholder must still be indexed");
    assert_eq!(
        after.blocks, adopted.blocks,
        "re-offering an unchanged version must not change what the placeholder names"
    );
    assert_eq!(
        device_b.materialization_state(PATH),
        Some(MaterializationState::Placeholder),
        "re-offering an unchanged version must leave the placeholder a placeholder"
    );
    assert_eq!(
        device_b.blocks_held(&after),
        0,
        "re-offering a version already held started a fetch"
    );
}

/// An already-pinned path keeps following its peer, on the same folder that
/// refuses to fetch anything else.
///
/// The complement of the two tests above, and the reason they cannot be
/// satisfied by never fetching at all. A pin is a deliberate, user-initiated
/// request -- exactly the "something asks" that on-demand reserves content
/// transfer for -- and it does not expire when the file changes.
///
/// The reconciliation pass is the only thing that can honor it for a NEW
/// version: `hydration::pin` fetches the version that existed when the user
/// asked, and nothing re-runs it afterwards. The pass obtains its content up
/// front and then maps a record that still needs blocks to `RetryRequired`
/// without ever reaching for the transport itself -- so a pinned record the
/// pass declined to obtain would retry forever, and the pin would silently
/// stop meaning anything the moment the file was edited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_already_pinned_path_follows_a_new_version_in_an_on_demand_folder() {
    let _provider = placeholder_provider_present();
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let first = vec![0x33u8; 256 * 1024];
    std::fs::write(device_a.path(PATH), &first).unwrap();
    wait_until_with_context(
        || device_b.record(PATH).is_some(),
        Duration::from_secs(30),
        || "the on-demand folder never adopted the peer's file".into(),
    )
    .await;
    assert_eq!(
        device_b.blocks_held(&device_b.record(PATH).expect("just waited for it")),
        0,
        "the adoption must start from no content, or this test cannot tell a pin's fetch from \
         the eager fetching the other two tests forbid"
    );

    // Through the product's own entry point, not the raw index flag: `pin`
    // is what a user's request reaches, and it hydrates the version that
    // exists at that moment as part of being asked.
    yadorilink_daemon::hydration::pin(&device_b.state, GROUP, PATH).await.unwrap();
    let pinned = device_b.record(PATH).expect("the pinned path must still be indexed");
    assert_eq!(
        device_b.blocks_held(&pinned),
        pinned.blocks.len(),
        "pinning must hydrate the version that existed when the user asked"
    );

    // A NEW version of the same pinned path. Different bytes, so it needs
    // blocks this device cannot already have.
    let second = vec![0x34u8; 256 * 1024];
    std::fs::write(device_a.path(PATH), &second).unwrap();

    wait_until_with_context(
        || {
            device_b.record(PATH).is_some_and(|record| {
                record.blocks != pinned.blocks
                    && device_b.blocks_held(&record) == record.blocks.len()
            })
        },
        Duration::from_secs(30),
        || {
            let record = device_b.record(PATH);
            let held = record.as_ref().map(|r| device_b.blocks_held(r));
            let moved = record.as_ref().is_some_and(|r| r.blocks != pinned.blocks);
            format!(
                "a pinned path stopped following its peer: new_version={moved} blocks_held={held:?}. \
                 On-demand reserves fetching for a deliberate request, and a pin stays one across \
                 edits -- a pin that silently stops applying when the file changes is worse than \
                 no pin at all."
            )
        },
    )
    .await;
}

/// A pinned path's conflict copy is obtained, and its source stops being
/// outstanding.
///
/// The two rules this file states pull in opposite directions the moment a
/// pinned path forks. On-demand says fetch nothing that was not asked for;
/// conflict-copy correctness says a copy must materialize everywhere, or the
/// resolution that produced it can never complete. A conflict copy is not
/// something anyone pins -- it exists only because resolving the pinned
/// source produced it -- so it inherits the source's demand rather than
/// carrying one of its own.
///
/// Get that wrong by keying the on-demand filter on the copy's OWN path and
/// the copy is refused, materialization reports `RetryRequired`, and the
/// engine keeps the source outstanding forever because a copy derived from
/// it is unresolved: unbounded work, zero progress, on the on-demand path
/// only. Asserting that the copy appeared is not enough to catch that --
/// what has to be asserted is that the SOURCE stops needing another attempt.
///
/// Three devices, and the shape matters. Two writers author their own
/// version of one path before either has seen the other, which is the only
/// way the path genuinely forks; the on-demand reader then pairs with both
/// and holds NEITHER version's blocks. That is what makes the assertion
/// unambiguous. With the reader as one of the two writers, whichever side
/// wins decides whether obtaining the copy is a real fetch or a rename of
/// content the reader already authored -- and which side wins alternates
/// between runs here, so the test would have passed for the wrong reason
/// about half the time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_paths_conflict_copy_is_obtained_and_its_source_settles() {
    let _provider = placeholder_provider_present();
    let writer_a = setup_device("device-a");
    let writer_b = setup_device("device-b");
    let reader = setup_device("device-r");

    // A linked group with no policy is fail-closed: local emission is
    // withheld entirely, so an unpaired device captures nothing at all. The
    // pairing helper installs this on the way past, which is too late here --
    // the whole point is that both writers author BEFORE they meet.
    let groups = [GROUP.to_string()];
    for device in [&writer_a, &writer_b, &reader] {
        support::install_bootstrap_policy(&device.state, &groups);
    }

    std::fs::write(writer_a.path(PATH), vec![0x41u8; 256 * 1024]).unwrap();
    std::fs::write(writer_b.path(PATH), vec![0x42u8; 256 * 1024]).unwrap();
    start_watching(&writer_a, MaterializationPolicy::Eager);
    start_watching(&writer_b, MaterializationPolicy::Eager);
    start_watching(&reader, MaterializationPolicy::OnDemand);
    wait_until_with_context(
        || writer_a.record(PATH).is_some() && writer_b.record(PATH).is_some(),
        Duration::from_secs(30),
        || {
            format!(
                "both writers must author their own version before meeting, or the path never \
                 forks: a={:?} b={:?}",
                writer_a.record(PATH).is_some(),
                writer_b.record(PATH).is_some(),
            )
        },
    )
    .await;

    pair(&reader, &writer_a).await;
    pair(&reader, &writer_b).await;

    // Adopted as a placeholder, with nothing fetched -- this file's own first
    // property, restated here because the rest of the test depends on it: the
    // reader holds neither version's blocks.
    wait_until_with_context(
        || reader.record(PATH).is_some_and(|record| reader.blocks_held(&record) == 0),
        Duration::from_secs(60),
        || {
            format!(
                "the on-demand reader never adopted the forked path as a placeholder: \
                 record={:?}",
                reader.record(PATH).map(|r| reader.blocks_held(&r))
            )
        },
    )
    .await;

    // Pinning is the request. It covers the path, and with it every copy the
    // path's own resolution derives.
    //
    // Retried through `HydrationFailed`, which `hydrate`'s own doc comment
    // states is a transient a real consumer must retry: this pins the moment
    // the placeholder appears, while the fork's resolution is still settling.
    // Not retrying would be asserting that the very first attempt lands in
    // exactly the right window.
    let mut pin_attempts = 0;
    loop {
        match yadorilink_daemon::hydration::pin(&reader.state, GROUP, PATH).await {
            Ok(()) => break,
            Err(error) if pin_attempts < 5 => {
                pin_attempts += 1;
                tracing::warn!(%error, pin_attempts, "pin failed, retrying");
            }
            Err(error) => panic!(
                "pinning a path the reader has already adopted must \
                 eventually succeed, after {pin_attempts} retries: {error}"
            ),
        }
    }

    // The copy must actually arrive with its content -- not merely be named.
    // Whichever version lost, its blocks live on the writer that authored it
    // and nowhere else, so this is always a real fetch.
    wait_until_with_context(
        || {
            support::real_entry_names(reader.root.path()).iter().any(|name| {
                name.contains("conflicted copy")
                    && reader
                        .record(name)
                        .is_some_and(|record| reader.blocks_held(&record) == record.blocks.len())
            })
        },
        Duration::from_secs(60),
        || {
            format!(
                "a pinned path's conflict copy never obtained its content on the on-demand \
                 device. Entries: {:?}. A copy inherits its source's demand; refusing it leaves \
                 the source permanently unresolvable.",
                support::real_entry_names(reader.root.path())
            )
        },
    )
    .await;

    // And the source stops being outstanding. Without this the test would
    // pass while the engine re-drove the same path forever.
    wait_until_with_context(
        || {
            reader
                .materialization_state(PATH)
                .is_some_and(|state| state != MaterializationState::Hydrating)
        },
        Duration::from_secs(60),
        || {
            format!(
                "the pinned source never settled: state={:?}. A source whose derived copy cannot \
                 be obtained is retried forever -- unbounded work, zero progress.",
                reader.materialization_state(PATH)
            )
        },
    )
    .await;
}
