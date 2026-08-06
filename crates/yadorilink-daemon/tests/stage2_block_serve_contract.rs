//! RED acceptance coverage for convergence-engine stage 2: the source-side
//! shared block-serving scheduler, byte fairness, explicit congestion signals,
//! and separation of content backpressure from control/metadata traffic.
//!
//! These tests intentionally exercise observable behavior through real
//! `PeerSyncSession`s rather than naming a particular `BlockServeEngine` API.
//! The implementation may choose its internal queue/coalescer types freely.
//!
//! Stage-1 behavior is expected to fail these tests:
//! - identical requests arriving through different peer sessions each perform
//!   their own source-store read;
//! - enough stalled `BlockRequest` handlers consume the ordinary-message
//!   permits and delay a control query on the same session;
//! - one peer/group can place a large FIFO backlog ahead of later work from a
//!   different peer or group;
//! - the wire schema has no explicit serve-credit or Busy/Redirect contract.

mod support;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tokio::task::JoinSet;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::{BlockStore, ContentHash, FsBlockStore, GcReport, StorageError};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, VersionHash};
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};

const GROUP_A: &str = "stage2-group-a";
const GROUP_B: &str = "stage2-group-b";

#[derive(Clone, Copy)]
enum ReadMode {
    Delay(Duration),
    Gate,
}

#[derive(Default)]
struct ReadState {
    calls_by_hash: HashMap<String, usize>,
    entered: Vec<String>,
    permits: usize,
    immediate_hashes: HashSet<String>,
}

/// A real `FsBlockStore` with deterministic observation/control around `get`.
///
/// `Delay` widens the overlap window so identical cross-session requests must
/// coalesce. `Gate` records every source read and blocks it until the test
/// releases a permit, making queue order and control-lane starvation directly
/// observable without relying on machine speed.
struct InstrumentedBlockStore {
    inner: Arc<FsBlockStore>,
    mode: ReadMode,
    state: Mutex<ReadState>,
    changed: Condvar,
}

impl InstrumentedBlockStore {
    fn new(inner: Arc<FsBlockStore>, mode: ReadMode) -> Self {
        Self { inner, mode, state: Mutex::new(ReadState::default()), changed: Condvar::new() }
    }

    fn calls_for(&self, hash_hex: &str) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .calls_by_hash
            .get(hash_hex)
            .copied()
            .unwrap_or(0)
    }

    fn allow_immediate(&self, hash_hex: &str) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .immediate_hashes
            .insert(hash_hex.to_string());
    }

    fn release(&self, count: usize) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.permits = state.permits.saturating_add(count);
        self.changed.notify_all();
    }

    fn wait_for_entered_at_least(&self, count: usize, timeout: Duration) -> usize {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        while state.entered.len() < count {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let (next, _) = self
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|p| p.into_inner());
            state = next;
        }
        state.entered.len()
    }

    fn entered_position(&self, hash_hex: &str) -> Option<usize> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entered
            .iter()
            .position(|h| h == hash_hex)
    }
}

impl BlockStore for InstrumentedBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.inner.put(data)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let immediate = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            *state.calls_by_hash.entry(hash.to_string()).or_insert(0) += 1;
            state.entered.push(hash.to_string());
            let immediate = state.immediate_hashes.contains(hash);
            self.changed.notify_all();

            if matches!(self.mode, ReadMode::Gate) && !immediate {
                while state.permits == 0 {
                    state = self.changed.wait(state).unwrap_or_else(|p| p.into_inner());
                }
                state.permits -= 1;
            }
            immediate
        };

        if !immediate {
            if let ReadMode::Delay(delay) = self.mode {
                std::thread::sleep(delay);
            }
        }
        self.inner.get(hash)
    }

    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
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

    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.inner.sweep(live, grace_cutoff, dry_run)
    }
}

struct Device {
    device_id: String,
    state: Arc<DaemonState>,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
    _roots: Vec<tempfile::TempDir>,
}

fn new_plain_device(device_id: &str, groups: &[&str]) -> Device {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    new_device(device_id, groups, store, store_dir)
}

fn new_instrumented_device(
    device_id: &str,
    groups: &[&str],
    mode: ReadMode,
) -> (Device, Arc<InstrumentedBlockStore>) {
    let store_dir = tempfile::tempdir().unwrap();
    let inner = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let instrumented = Arc::new(InstrumentedBlockStore::new(inner, mode));
    let store: Arc<dyn BlockStore + Send + Sync> = instrumented.clone();
    (new_device(device_id, groups, store, store_dir), instrumented)
}

fn new_device(
    device_id: &str,
    groups: &[&str],
    store: Arc<dyn BlockStore + Send + Sync>,
    store_dir: tempfile::TempDir,
) -> Device {
    let (sync_state, index_dir) = support::open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.to_string(), Arc::new(sync_state), store);
    support::ensure_device_signing_key(&state);
    let mut roots = Vec::new();
    for group in groups {
        let root = tempfile::tempdir().unwrap();
        state.replica_coordinator.link_repository().add_link(&root.path().to_string_lossy(), group).unwrap();
        roots.push(root);
    }
    Device {
        device_id: device_id.to_string(),
        state,
        _store_dir: store_dir,
        _index_dir: index_dir,
        _roots: roots,
    }
}

#[derive(Clone)]
struct SeededBlock {
    path: String,
    hash: Vec<u8>,
    hash_hex: String,
    data: Vec<u8>,
    version_hash: VersionHash,
    version_blocks: Vec<VersionBlock>,
}

fn seeded_data(seed: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i.wrapping_mul(131) + seed.wrapping_mul(17) + i / 7) % 251) as u8).collect()
}

fn seed_block(device: &Device, group: &str, path: &str, data: Vec<u8>) -> SeededBlock {
    let hash_hex = device.state.block_store.put(&data).unwrap();
    let hash = hex::decode(&hash_hex).unwrap();
    device
        .state
        .replica_coordinator
        .change_history_repository().record_group_block_provenance(group, std::slice::from_ref(&hash))
        .unwrap();

    let record = FileRecord {
        path: path.to_string(),
        size: data.len() as u64,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: hash.clone(), offset: 0, size: data.len() as u32 }],
        deleted: false,
    };
    device
        .state
        .replica_coordinator
        .file_index_repository().upsert_file(
            group,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let version_blocks =
        vec![VersionBlock { hash: BlockHash(hash.clone()), size: data.len() as u32 }];
    let version = FileVersion::new(
        version_blocks.clone(),
        data.len() as u64,
        FileMeta {
            mtime_unix_nanos: 0,
            exec_bit: false,
            symlink_target: None,
            record_kind: RecordKind::File,
        },
    );

    SeededBlock {
        path: path.to_string(),
        hash,
        hash_hex,
        data,
        version_hash: version.version_hash,
        version_blocks,
    }
}

async fn connect(source: &Device, requester: &Device, groups: &[&str]) {
    let groups = groups.iter().map(|g| (*g).to_string()).collect::<Vec<_>>();
    support::connect_two_daemons(
        &source.state,
        &source.device_id,
        &requester.state,
        &requester.device_id,
        &groups,
    )
    .await;
}

fn session_to(device: &Device, peer_id: &str) -> Arc<PeerSyncSession> {
    device
        .state
        .peers
        .session(peer_id)
        .unwrap_or_else(|| panic!("no session from {} to {peer_id}", device.device_id))
}

fn spawn_fetches(
    session: Arc<PeerSyncSession>,
    group: &str,
    blocks: &[SeededBlock],
) -> JoinSet<()> {
    let mut tasks = JoinSet::new();
    for block in blocks.iter().cloned() {
        let session = session.clone();
        let group = group.to_string();
        tasks.spawn(async move {
            let received = session
                .fetch_block(&group, &block.path, &block.hash)
                .await
                .expect("block request must not fail")
                .expect("source must return the block");
            assert_eq!(&received[..], block.data.as_slice());
        });
    }
    tasks
}

async fn drain(tasks: &mut JoinSet<()>, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        while let Some(result) = tasks.join_next().await {
            result.expect("fetch task panicked");
        }
    })
    .await
    .expect("fetch tasks did not finish after the source gate opened");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn identical_block_requested_by_many_peers_is_read_once_and_fanned_out() {
    support::ensure_isolated_config_dir();
    let (source, store) =
        new_instrumented_device("source", &[GROUP_A], ReadMode::Delay(Duration::from_millis(300)));
    let block = seed_block(&source, GROUP_A, "shared.bin", seeded_data(1, 128 * 1024));

    let requesters =
        (0..6).map(|i| new_plain_device(&format!("requester-{i}"), &[GROUP_A])).collect::<Vec<_>>();
    for requester in &requesters {
        connect(&source, requester, &[GROUP_A]).await;
    }

    let barrier = Arc::new(tokio::sync::Barrier::new(requesters.len() + 1));
    let mut tasks = JoinSet::new();
    for requester in &requesters {
        let session = session_to(requester, &source.device_id);
        let barrier = barrier.clone();
        let block = block.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            let received = session
                .fetch_block(GROUP_A, &block.path, &block.hash)
                .await
                .expect("request must succeed")
                .expect("source must return the block");
            assert_eq!(&received[..], block.data.as_slice());
        });
    }
    barrier.wait().await;
    drain(&mut tasks, Duration::from_secs(15)).await;

    assert_eq!(
        store.calls_for(&block.hash_hex),
        1,
        "six requesters for one (group, hash) must share one source read/hash/compress operation"
    );
}

/// Regression for a confirmed cross-group response-correlation bug: two
/// folder groups sharing one peer connection can legitimately reference
/// the IDENTICAL content hash (e.g. the same file copied into both), and
/// the source can legitimately answer them DIFFERENTLY -- GROUP_A has
/// recorded provenance for this hash and gets `Found`, GROUP_B's index
/// references the same hash/path but this device never recorded GROUP_B
/// provenance for it, so it must be refused. Correlating replies by
/// `block_hash` alone (the pre-fix behavior) cannot tell these two
/// concurrent requests apart: whichever reply lands first on the wire
/// resolves BOTH waiters, so GROUP_B's request could silently receive
/// GROUP_A's `Found` bytes -- bypassing GROUP_B's own provenance check
/// entirely. `request_id`-scoped correlation on the negotiated path must
/// keep these two outcomes fully independent regardless of arrival order.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_requests_for_the_same_hash_across_groups_never_cross_wire_their_outcomes() {
    support::ensure_isolated_config_dir();
    let (source, _store) = new_instrumented_device(
        "source",
        &[GROUP_A, GROUP_B],
        ReadMode::Delay(Duration::from_millis(50)),
    );
    let requester = new_plain_device("requester", &[GROUP_A, GROUP_B]);

    // GROUP_A: real provenance recorded -- must be served.
    let block = seed_block(&source, GROUP_A, "shared.bin", seeded_data(1, 4096));

    // GROUP_B: the index references the IDENTICAL hash at a different
    // path, but this device never recorded GROUP_B provenance for it --
    // must be refused, no matter what GROUP_A's concurrent request gets.
    let group_b_path = "not-provenanced.bin";
    source
        .state
        .replica_coordinator
        .file_index_repository().upsert_file(
            GROUP_B,
            &FileRecord {
                path: group_b_path.to_string(),
                size: block.data.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo {
                    hash: block.hash.clone(),
                    offset: 0,
                    size: block.data.len() as u32,
                }],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect(&source, &requester, &[GROUP_A, GROUP_B]).await;
    let session = session_to(&requester, &source.device_id);

    let (group_a_result, group_b_result) = tokio::join!(
        session.fetch_block(GROUP_A, &block.path, &block.hash),
        session.fetch_block(GROUP_B, group_b_path, &block.hash),
    );

    let group_a_bytes = group_a_result
        .expect("request must not fail")
        .expect("GROUP_A has real recorded provenance and must be served");
    assert_eq!(&group_a_bytes[..], block.data.as_slice());

    let group_b_bytes = group_b_result.expect("request must not fail");
    assert!(
        group_b_bytes.is_none(),
        "GROUP_B has no recorded provenance for this hash and must be refused, even though a \
         concurrent GROUP_A request for the IDENTICAL hash was legitimately served -- hash-only \
         correlation would leak GROUP_A's Found bytes to this GROUP_B waiter instead"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 12)]
async fn stalled_content_requests_do_not_delay_control_messages_on_the_same_session() {
    support::ensure_isolated_config_dir();
    let (source, store) = new_instrumented_device("source", &[GROUP_A], ReadMode::Gate);
    let requester = new_plain_device("requester", &[GROUP_A]);

    let noisy = (0..72)
        .map(|i| {
            seed_block(
                &source,
                GROUP_A,
                &format!("bulk-{i:03}.bin"),
                seeded_data(100 + i, 16 * 1024),
            )
        })
        .collect::<Vec<_>>();
    let control = seed_block(&source, GROUP_A, "control-proof.bin", seeded_data(999, 1024));
    // The control query itself verifies this block. Keep that one read outside
    // the artificial content gate; only the ordinary BlockRequest flood stalls.
    store.allow_immediate(&control.hash_hex);

    connect(&source, &requester, &[GROUP_A]).await;
    requester.state.set_peer_group_full_replica(&source.device_id, GROUP_A, true);
    tokio::time::sleep(Duration::from_millis(200)).await;

    let session = session_to(&requester, &source.device_id);
    let mut noisy_tasks = spawn_fetches(session, GROUP_A, &noisy);
    let entered = store.wait_for_entered_at_least(64, Duration::from_secs(2));
    assert!(entered > 0, "the test never created source-side content pressure");

    let started = Instant::now();
    let confirmed = tokio::time::timeout(
        Duration::from_millis(750),
        requester.state.confirm_version_present_via_peer(
            GROUP_A,
            &control.path,
            control.version_hash,
            &control.version_blocks,
        ),
    )
    .await
    .expect(
        "VersionPresent control traffic was delayed behind stalled content handlers; \
         content flow control must use a separate logical lane",
    );
    assert!(confirmed, "the source held the exact control-proof version");
    assert!(
        started.elapsed() < Duration::from_millis(750),
        "control reply exceeded the stage-2 latency budget"
    );

    store.release(1_000);
    drain(&mut noisy_tasks, Duration::from_secs(15)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn late_small_requests_from_another_peer_and_group_cut_ahead_of_a_large_backlog() {
    support::ensure_isolated_config_dir();
    let (source, store) = new_instrumented_device("source", &[GROUP_A, GROUP_B], ReadMode::Gate);
    let peer_a = new_plain_device("peer-a", &[GROUP_A, GROUP_B]);
    let peer_b = new_plain_device("peer-b", &[GROUP_A]);

    let large_backlog = (0..96)
        .map(|i| {
            seed_block(
                &source,
                GROUP_A,
                &format!("large-{i:03}.bin"),
                seeded_data(2_000 + i, 64 * 1024),
            )
        })
        .collect::<Vec<_>>();
    let other_group =
        seed_block(&source, GROUP_B, "small-other-group.bin", seeded_data(9_001, 1024));
    let other_peer = seed_block(&source, GROUP_A, "small-other-peer.bin", seeded_data(9_002, 1024));

    connect(&source, &peer_a, &[GROUP_A, GROUP_B]).await;
    connect(&source, &peer_b, &[GROUP_A]).await;

    let session_a = session_to(&peer_a, &source.device_id);
    let session_b = session_to(&peer_b, &source.device_id);
    let mut tasks = spawn_fetches(session_a.clone(), GROUP_A, &large_backlog);

    // Let the old per-session FIFO establish a meaningful backlog. A stage-2
    // scheduler may intentionally start far fewer reads; either way there is
    // outstanding pressure before the two small requests arrive.
    let entered = store.wait_for_entered_at_least(16, Duration::from_secs(2));
    assert!(entered > 0, "the large backlog never reached the source");

    for (session, group, block) in
        [(session_a, GROUP_B, other_group.clone()), (session_b, GROUP_A, other_peer.clone())]
    {
        tasks.spawn(async move {
            let received = session
                .fetch_block(group, &block.path, &block.hash)
                .await
                .expect("small request must not fail")
                .expect("source must return the small block");
            assert_eq!(&received[..], block.data.as_slice());
        });
    }

    // A byte-fair source queue must choose both newly-active classes promptly,
    // rather than draining dozens of already-enqueued large reads first.
    for _ in 0..16 {
        if store.entered_position(&other_group.hash_hex).is_some()
            && store.entered_position(&other_peer.hash_hex).is_some()
        {
            break;
        }
        store.release(1);
        tokio::time::sleep(Duration::from_millis(40)).await;
    }

    let group_position = store.entered_position(&other_group.hash_hex);
    let peer_position = store.entered_position(&other_peer.hash_hex);
    assert!(
        group_position.is_some_and(|position| position < 32),
        "a small request from another group was starved behind the large backlog: \
         position={group_position:?}"
    );
    assert!(
        peer_position.is_some_and(|position| position < 32),
        "a small request from another peer was starved behind the large backlog: \
         position={peer_position:?}"
    );

    store.release(10_000);
    drain(&mut tasks, Duration::from_secs(20)).await;
}

#[test]
fn stage2_wire_schema_exposes_credit_and_explicit_congestion_outcomes() {
    let schema = include_str!("../../yadorilink-ipc-proto/proto/sync.proto");
    let lower = schema.to_ascii_lowercase();

    for required in [
        "max_inflight_requests",
        "max_inflight_bytes",
        "available_worker_slots",
        "estimated_queue_delay_ms",
    ] {
        assert!(
            lower.contains(required),
            "serve-credit advertisement is missing required field {required:?}"
        );
    }

    let cluster_start = lower.find("message clusterconfig").unwrap();
    let block_request_start = lower.find("message blockrequest").unwrap();
    let cluster = &lower[cluster_start..block_request_start];
    assert!(
        cluster.contains("reserved \"supports_block_serve_credit\""),
        "the removed capability bit must stay reserved so the v2 protocol has no fallback path"
    );
    assert!(cluster.contains("uint32 protocol_version"));
    assert!(!cluster
        .lines()
        .any(|line| line.trim_start().starts_with("bool supports_block_serve_credit =")));

    let response_start = lower.find("message blockresponse").unwrap();
    let response_end = lower[response_start..]
        .find("// change-history dag exchange")
        .map(|relative| response_start + relative)
        .unwrap_or(lower.len());
    let response = &lower[response_start..response_end];
    for required in [
        "busy",
        "retry_after_ms",
        "queue_depth",
        "redirect",
        "candidate_device_ids",
        "rejected",
        "reason",
    ] {
        assert!(
            response.contains(required),
            "BlockResponse is missing explicit stage-2 outcome field/variant {required:?}"
        );
    }
}
