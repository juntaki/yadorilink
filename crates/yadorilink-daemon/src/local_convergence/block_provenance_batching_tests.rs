#![cfg(test)]

use super::*;
use crate::replica_coordinator::ReplicaCoordinator;
use ed25519_dalek::SigningKey;
use yadorilink_local_storage::{
    BlockStore, ContentHash, LocallyHashedBlock, SegmentBlockStore, StorageError,
};
use yadorilink_peer_session::peer_session::*;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::file::{BlockInfo, FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, SyncPath};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::conflict::{resolve_path_heads, PathResolution};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sync_sqlite::dag_store::{self, ChangeEmitter};

const GROUP: &str = "provenance-batching-group";

/// Wraps a real `SegmentBlockStore` and can be told to fail exactly the next
/// `put` of one specific content payload -- for the "a block whose
/// `store.put` fails is never included in provenance" regression, which
/// needs a deterministic, single-block failure a real filesystem-backed
/// store cannot easily be made to produce for just one hash among
/// several. Every other call forwards to the real store unchanged.
struct FailingBlockStore {
    inner: Arc<SegmentBlockStore>,
    fail_content: std::sync::Mutex<Option<Vec<u8>>>,
}

impl FailingBlockStore {
    fn new(inner: Arc<SegmentBlockStore>) -> Arc<Self> {
        Arc::new(Self { inner, fail_content: std::sync::Mutex::new(None) })
    }

    /// One-shot: the NEXT `put` call whose bytes equal `content` fails;
    /// every other call (including a later `put` of this exact content,
    /// were there one) succeeds normally.
    fn fail_next_put_of(&self, content: &[u8]) {
        *self.fail_content.lock().unwrap_or_else(|p| p.into_inner()) = Some(content.to_vec());
    }
}

impl yadorilink_peer_session::ports::BlockContentStore for FailingBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        let mut guard = self.fail_content.lock().unwrap_or_else(|p| p.into_inner());
        if guard.as_deref() == Some(data) {
            *guard = None;
            return Err(StorageError::Io(std::io::Error::other(
                "simulated store.put failure (block_provenance_batching_tests)",
            )));
        }
        drop(guard);
        BlockStore::put(self.inner.as_ref(), data)
    }

    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        BlockStore::put_prepared(self.inner.as_ref(), prepared)
    }

    /// The fault has to be injectable HERE, not only in `put`: the
    /// receive path commits through `put_prepared_batch`, so a fake
    /// that only fails `put` would silently stop injecting anything
    /// and leave the test asserting against a store that never failed.
    ///
    /// Fails the whole batch if ANY block in it is the armed content,
    /// which is what a real all-or-nothing batch commit does.
    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        let mut guard = self.fail_content.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(armed) = guard.as_deref() {
            if prepared.iter().any(|block| block.bytes() == armed) {
                *guard = None;
                return Err(StorageError::Io(std::io::Error::other(
                    "simulated store.put failure (block_provenance_batching_tests)",
                )));
            }
        }
        drop(guard);
        BlockStore::put_prepared_batch(self.inner.as_ref(), prepared)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        BlockStore::get(self.inner.as_ref(), hash)
    }

    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        BlockStore::present_blocks(self.inner.as_ref(), hashes)
    }
}

/// Two real `PeerSyncSession`s over an in-memory channel: `session_a`
/// serves blocks (real `SegmentBlockStore` + real `ReplicaCoordinator`), `session_b`
/// is the one whose `ensure_blocks_present` these tests call directly.
/// `store_b` is caller-supplied so the store.put-failure test can swap
/// in `FailingBlockStore`; every other test passes a plain real store.
async fn connected_pair(
    store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
) -> (
    Arc<PeerSyncSession>,
    Arc<ReplicaCoordinator>,
    Arc<SegmentBlockStore>,
    Arc<PeerSyncSession>,
    Arc<ReplicaCoordinator>,
    Arc<super::LocalConvergenceExecutor>,
) {
    let (channel_a, channel_b) =
        yadorilink_peer_session::ports::InMemoryPeerChannel::connected_pair();
    let state_a = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state_b = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    // A serves blocks and never materializes, but a real link row still
    // needs a local path.
    let root_a = tempfile::tempdir().unwrap().keep();
    state_a.link_repository().add_link(&root_a.to_string_lossy(), GROUP).unwrap();
    // B needs a REAL disk root: `prepare_ordinary_projected_upsert`
    // reaches `local_file_path`/`verify_write_target` (unlike a call
    // straight to `ensure_blocks_present`, which never touches disk
    // paths at all) -- `ordinary_batch_tests::Harness` needs the exact
    // same thing, for the exact same reason.
    let root_b = tempfile::tempdir().unwrap().keep();
    state_b.link_repository().add_link(&root_b.to_string_lossy(), GROUP).unwrap();
    state_b
        .link_repository()
        .set_materialization_policy(
            &root_b.to_string_lossy(),
            yadorilink_replica_domain::session_state::MaterializationPolicy::Eager,
        )
        .unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(&root_b, GROUP, state_b.as_ref())
        .unwrap();
    // `keep()`, like `root_b` above: this fixture returns the store to
    // its caller, so the directory has to outlive this function. A
    // `TempDir` dropped here would delete the store's index and
    // segments out from under the handle the caller is still holding.
    let store_a = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let transports_a = yadorilink_peer_session::ports::in_memory_transports(&channel_a);
    let transports_b = yadorilink_peer_session::ports::in_memory_transports(&channel_b);
    // This fixture drives A's own block-lane accept loop below -- the
    // in-memory double's stand-in for `sync_stack.rs`'s `serve_peer_lanes`,
    // since block streams arrive no other way (see `serve_block_stream`'s
    // own doc comment).
    let channel_a_block_lane = channel_a.clone();
    let session_a = PeerSyncSession::over_substrate(
        "device-a".to_string(),
        "device-b".to_string(),
        state_a.clone() as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        crate::replica_coordinator::engine_ports::build_peer_replica_engine(
            &state_a,
            store_a.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
        ),
        store_a.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
        vec![GROUP.to_string()],
        HashMap::new(),
        transports_a,
        None,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::test_permissive(),
    );
    // A must have a `BlockServeEngine` installed to answer ANY
    // `BlockRequest` at all -- without one, `handle_block_request`
    // rejects every request with "no BlockServeEngine installed"
    // before ever reaching the referenced/provenance checks these
    // tests actually want to exercise. Generous limits: this module's
    // block-serving budget itself is not under test.
    session_a.set_block_serve_engine(yadorilink_peer_session::block_serve::BlockServeEngine::new(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        16,
    ));
    let deps_b = yadorilink_peer_session::peer_session::PeerSyncSessionDeps::test_permissive();
    let sync_roots_b = HashMap::from([(GROUP.to_string(), root_b)]);
    let session_b = PeerSyncSession::over_substrate(
        "device-b".to_string(),
        "device-a".to_string(),
        state_b.clone() as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        crate::replica_coordinator::engine_ports::build_peer_replica_engine(
            &state_b,
            store_b.clone(),
        ),
        store_b.clone(),
        vec![GROUP.to_string()],
        sync_roots_b.clone(),
        transports_b,
        None,
        deps_b.clone(),
    );
    // B's executor: the local work the session used to own, built from the
    // same dependencies that session was handed.
    let convergence_b = super::LocalConvergenceExecutor::new(
        state_b.clone(),
        "device-b".to_string(),
        deps_b.root_commit_authority_provider.clone(),
        deps_b.pending_local_change_flush.clone(),
        sync_roots_b,
        store_b,
        deps_b.block_write_activity_provider.clone(),
        super::HeadroomPolicy::disabled(),
    );
    // A's own block-lane accept loop -- only A ever serves in this
    // module (see this function's own doc comment), so B needs none.
    // One task per accepted stream, matching production's own
    // `serve_peer_lanes`.
    tokio::spawn({
        let session = session_a.clone();
        async move {
            while let Some(stream) = channel_a_block_lane.accept_block_stream().await {
                let session = session.clone();
                tokio::spawn(async move { session.serve_block_stream(stream).await });
            }
        }
    });
    (session_a, state_a, store_a, session_b, state_b, convergence_b)
}

/// Seeds `content` into A's real block store and marks it BOTH
/// referenced (a live `FileRecord` at `path` whose blocks include the
/// resulting hash) and provenanced there -- `block_request_checks_off_
/// runtime`'s own two gates, both of which A's real `handle_block_
/// request` enforces on every incoming request. Returns the raw hash.
fn seed_servable_block(
    state_a: &ReplicaCoordinator,
    store_a: &SegmentBlockStore,
    content: &[u8],
) -> Vec<u8> {
    let hash = hex::decode(store_a.put(content).unwrap()).unwrap();
    state_a
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    hash
}

/// Builds the `FileRecord` A serves at `path` for `blocks` (each
/// `(hash, content_len)`), covering the whole-record referencing check
/// in one call regardless of how many blocks the test seeded.
fn seed_servable_record(
    state_a: &Arc<ReplicaCoordinator>,
    path: &str,
    blocks: &[(Vec<u8>, usize)],
) {
    let mut offset = 0u64;
    let mut block_infos = Vec::with_capacity(blocks.len());
    let mut total_size = 0u64;
    for (hash, len) in blocks {
        block_infos.push(BlockInfo { hash: hash.clone(), offset, size: *len as u32 });
        offset += *len as u64;
        total_size += *len as u64;
    }
    let version = FileVersion::new(
        block_infos
            .iter()
            .map(|b| VersionBlock { hash: BlockHash(b.hash.clone()), size: b.size })
            .collect(),
        total_size,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let record = FileRecord {
        path: path.to_string(),
        size: total_size,
        mtime_unix_nanos: 0,
        blocks: block_infos,
        deleted: false,
    };
    // Indexing the row is not enough: block-serving authorization reads
    // the PUBLISHED view, so A must emit the change AND publish it, or
    // it will refuse to serve bytes it demonstrably holds.
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let emitter = ChangeEmitter::new("device-a", signing_key.clone());
    let change_hash = state_a
        .upsert_file_emitting_change(
            GROUP,
            &record,
            "device-a",
            yadorilink_replica_domain::session_state::ChangeContent {
                ops: vec![Op::Put {
                    path: SyncPath(path.to_string()),
                    version: version.version_hash,
                    origin: PutOrigin::Direct,
                }],
                versions: std::slice::from_ref(&version),
            },
            None,
            None,
            crate::replica_coordinator::ReplicaChangeEmission {
                emitter: &emitter,
                permit: &RootCommitPermit::for_tests(),
            },
        )
        .unwrap();
    let change = state_a
        .sqlite()
        .dag_get_change(&change_hash)
        .unwrap()
        .expect("the change just emitted must be readable back");
    // Strictly increasing per (group, device), as real issuance is.
    let seq = next_checkpoint_seq();
    super::published_fixture::publish_change(state_a, &signing_key, seq, &change);
}

/// A's checkpoint sequence, shared across every record one fixture
/// seeds: `attach_authorization_evidence` refuses a reused sequence for
/// the same device, exactly as real issuance would.
fn next_checkpoint_seq() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

/// A `FileRecord` B hands to `ensure_blocks_present`, referencing
/// `blocks` at `path` -- deliberately NOT seeded into `state_b` at all
/// (that is exactly what forces a real fetch: an unseeded row is simply
/// absent, so `ensure_blocks_present`'s own metadata reads all resolve
/// to their defaults, which every test here accepts).
/// The version a `record_for` record is. These tests seed plain
/// `File` rows with no mode, target or xattrs, so the record alone
/// determines it -- which is exactly the payload provenance
/// `ensure_blocks_present` now requires of its caller.
fn version_of(record: &FileRecord) -> yadorilink_replica_domain::ids::VersionHash {
    FileVersion::from_index_row(
        record.blocks.clone(),
        record.size,
        record.mtime_unix_nanos,
        RecordKind::File,
        None,
        None,
        Vec::new(),
    )
    .version_hash
}

fn record_for(path: &str, blocks: &[(Vec<u8>, usize)]) -> FileRecord {
    let mut offset = 0u64;
    let mut block_infos = Vec::with_capacity(blocks.len());
    let mut total_size = 0u64;
    for (hash, len) in blocks {
        block_infos.push(BlockInfo { hash: hash.clone(), offset, size: *len as u32 });
        offset += *len as u64;
        total_size += *len as u64;
    }
    FileRecord {
        path: path.to_string(),
        size: total_size,
        mtime_unix_nanos: 0,
        blocks: block_infos,
        deleted: false,
    }
}

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The property this batching exists to move: durability barriers
/// scale with the number of COMMIT GROUPS, not with the number of
/// blocks received.
///
/// Asserted against `SegmentBlockStore`'s own barrier hook, which
/// fires once per durable group -- the same instrument the storage
/// layer's own tests use, so this is a real barrier count and not a
/// proxy for one. Before batching, this path issued one `store.put`
/// per block and the count below was exactly `BLOCKS`.
///
/// The bound asserted is deliberately loose (`<= 3` for 64 blocks
/// rather than exactly 1): fetches complete out of order through a
/// `FuturesUnordered`, and the final partial batch plus at most one
/// `MAX_COMMITS_IN_FLIGHT` drain can legitimately split the work. A
/// tight equality here would be a flaky test asserting scheduler
/// determinism that does not exist. What matters, and what this
/// catches, is a regression back to per-block barriers -- which would
/// read 64, not 3.
#[tokio::test]
async fn barriers_scale_with_commit_groups_not_with_block_count() {
    const BLOCKS: usize = 64;

    let concrete = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let barriers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&barriers);
    concrete.install_durability_barrier_hook_for_tests(move || {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> = concrete;
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b.clone()).await;

    let path = "many-small-blocks.bin";
    // Distinct content per block: identical bytes would dedup to one
    // hash and quietly turn this into a one-block test.
    let contents: Vec<Vec<u8>> =
        (0..BLOCKS).map(|i| format!("block-number-{i:04}").into_bytes()).collect();
    let blocks: Vec<(Vec<u8>, usize)> =
        contents.iter().map(|c| (seed_servable_block(&state_a, &store_a, c), c.len())).collect();
    seed_servable_record(&state_a, path, &blocks);

    let record = record_for(path, &blocks);
    let all_present = convergence_b
        .ensure_blocks_present(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            path,
            &record,
            &version_of(&record),
            TIMEOUT,
        )
        .await
        .unwrap();
    assert!(all_present, "every block was servable, so all of them must arrive");

    let observed = barriers.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        observed <= 3,
        "{BLOCKS} received blocks must share a handful of durability barriers, not one \
         each -- observed {observed}"
    );
    assert!(observed >= 1, "the blocks must actually have been committed");

    // The barrier saving must not have cost correctness: every block
    // is genuinely readable back from B's own store.
    for (hash, _) in &blocks {
        let hex_hash = hex::encode(hash);
        assert!(
            store_b.get(&hex_hash).is_ok(),
            "block {hex_hash} was reported present but is not readable from the store"
        );
    }
    let _ = state_b;
}

/// Requirement 1: multiple newly-fetched blocks cause exactly ONE
/// provenance batch containing every successful hash, not one call per
/// block.
#[tokio::test]
async fn multiple_newly_fetched_blocks_are_recorded_in_one_batch() {
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b).await;

    let path = "multi-block.bin";
    let contents: Vec<&[u8]> = vec![b"block-one", b"block-two", b"block-three"];
    let blocks: Vec<(Vec<u8>, usize)> =
        contents.iter().map(|c| (seed_servable_block(&state_a, &store_a, c), c.len())).collect();
    seed_servable_record(&state_a, path, &blocks);

    let record = record_for(path, &blocks);
    let all_present = convergence_b
        .ensure_blocks_present(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            path,
            &record,
            &version_of(&record),
            TIMEOUT,
        )
        .await
        .unwrap();
    assert!(all_present, "every block was genuinely servable by A");

    let batches = state_b.test_observers.provenance_batches();
    assert_eq!(
        batches.len(),
        1,
        "3 newly-fetched blocks in ONE ensure_blocks_present call must produce exactly one \
         batched record_group_block_provenance call, not one per block: {batches:?}"
    );
    let mut recorded: Vec<Vec<u8>> = batches[0].clone();
    recorded.sort();
    let mut expected: Vec<Vec<u8>> = blocks.iter().map(|(h, _)| h.clone()).collect();
    expected.sort();
    assert_eq!(recorded, expected, "the one batch must contain every successfully-fetched hash");
}

/// Requirement 2: a partially successful fetch (one block never
/// servable by A, so `all_present` ends up `false`) still records
/// provenance for the blocks that DID succeed -- a later retry must not
/// have to re-fetch content it already durably stored.
#[tokio::test]
async fn partial_success_still_batches_the_successful_subset() {
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b).await;

    let path = "partial.bin";
    let good_hash = seed_servable_block(&state_a, &store_a, b"servable-block");
    // A never learns about this hash at all (no `store.put`, no
    // provenance, not part of any seeded record) -- A's own
    // `block_request_is_referenced` and `group_has_block_provenance`
    // both answer false for it, so every attempt reports NotReferenced/
    // not_found, exhausting `NOT_FOUND_RETRY_ATTEMPTS` and yielding
    // `BlockFetchOutcome::Missing`.
    let missing_hash: Vec<u8> = vec![0xEE; 32];
    seed_servable_record(&state_a, path, &[(good_hash.clone(), b"servable-block".len())]);

    let record = record_for(
        path,
        &[(good_hash.clone(), b"servable-block".len()), (missing_hash.clone(), 9)],
    );
    let all_present = convergence_b
        .ensure_blocks_present(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            path,
            &record,
            &version_of(&record),
            TIMEOUT,
        )
        .await
        .unwrap();
    assert!(!all_present, "the never-served block must leave all_present false");

    let batches = state_b.test_observers.provenance_batches();
    assert_eq!(batches.len(), 1, "the successful subset must still be flushed in one batch");
    assert_eq!(
        batches[0],
        vec![good_hash.clone()],
        "only the genuinely-fetched hash may be recorded -- never the missing one"
    );
}

/// Requirement 3 (and the practical, checkable form of the crash-order
/// invariant: provenance can only be attempted after durable block
/// storage): a block whose durable commit fails must never appear in
/// any recorded provenance batch.
///
/// The sibling half of this test changed when the receive path moved
/// from a per-block `store.put` to a batched `put_prepared_batch`, and
/// the change is deliberate. A batch commit is all-or-nothing, so when
/// it fails NOTHING in it is durable -- including the sibling that
/// would have stored fine on its own. Asserting that the sibling keeps
/// its provenance would now be asserting a defect: the sibling's bytes
/// are not on disk. Both blocks here fit in one batch (two blocks, far
/// under `RECEIVE_COMMIT_BATCH_BLOCKS`), so the correct expectation is
/// that neither is provenanced and the next attempt re-fetches both.
///
/// What the test therefore checks is the invariant itself rather than
/// a count: every hash that reached `record_group_block_provenance` is
/// a hash the block store genuinely holds. That is the property the
/// ordering exists to protect, it is deterministic regardless of which
/// blocks land in which batch, and it would catch a future regression
/// that this test's older sibling-count assertion would not.
#[tokio::test]
async fn a_block_whose_store_put_fails_is_never_recorded() {
    let failing_store = FailingBlockStore::new(Arc::new(
        SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap(),
    ));
    let good_content: &[u8] = b"this-block-is-fine";
    let bad_content: &[u8] = b"this-block-fails-to-store";
    failing_store.fail_next_put_of(bad_content);
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> = failing_store;
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b.clone()).await;

    let path = "one-fails.bin";
    let good_hash = seed_servable_block(&state_a, &store_a, good_content);
    let bad_hash = seed_servable_block(&state_a, &store_a, bad_content);
    seed_servable_record(
        &state_a,
        path,
        &[(good_hash.clone(), good_content.len()), (bad_hash.clone(), bad_content.len())],
    );

    let record = record_for(
        path,
        &[(good_hash.clone(), good_content.len()), (bad_hash.clone(), bad_content.len())],
    );
    let result = convergence_b
        .ensure_blocks_present(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            path,
            &record,
            &version_of(&record),
            TIMEOUT,
        )
        .await;
    assert!(
        result.is_err(),
        "a store.put failure must surface as an error from ensure_blocks_present, not a \
         silent Ok(false)"
    );

    let batches = state_b.test_observers.provenance_batches();
    let all_recorded: Vec<Vec<u8>> = batches.into_iter().flatten().collect();
    assert!(
        !all_recorded.contains(&bad_hash),
        "the block whose durable commit failed must never be recorded as provenanced: \
         {all_recorded:?}"
    );
    // The invariant, checked directly against the store rather than
    // inferred from which blocks were expected to survive: a recorded
    // hash names a block this device actually holds.
    for recorded in &all_recorded {
        let hex_hash = hex::encode(recorded);
        assert!(
            store_b.get(&hex_hash).is_ok(),
            "provenance was recorded for {hex_hash}, which the block store does not hold -- \
             provenance must only ever attest to an already-durable block"
        );
    }
    assert!(
        !all_recorded.contains(&good_hash),
        "both blocks share one batch, and a batch commit is all-or-nothing, so the sibling \
         is NOT durable either and must not be provenanced: {all_recorded:?}"
    );
}

/// Requirement 4: a block already local AND already provenanced on B
/// never reaches `fetch_one_block` at all (the pre-existing
/// dedup check) -- confirms the new batching change doesn't
/// accidentally cause an empty or spurious `record_group_block_
/// provenance` call for the case that should do NOTHING.
#[tokio::test]
async fn already_local_and_provenanced_blocks_cause_no_provenance_write() {
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let (_session_a, _state_a, _store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b.clone()).await;

    let path = "already-local.bin";
    let content: &[u8] = b"already-here-on-b";
    let hash = hex::decode(store_b.put(content).unwrap()).unwrap();
    state_b
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();

    let record = record_for(path, &[(hash, content.len())]);
    let all_present = convergence_b
        .ensure_blocks_present(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            path,
            &record,
            &version_of(&record),
            TIMEOUT,
        )
        .await
        .unwrap();
    assert!(all_present, "an already-local, already-provenanced block must report present");

    assert!(
        state_b.test_observers.provenance_batches().is_empty(),
        "the dedup path must never reach the batched provenance write at all"
    );
}

/// Requirement 6: the pre-existing stale-refusal-clear behavior (a
/// successful fetch clears any prior `block_fetch_refusals` row for
/// this exact path/version/peer) must survive unaffected by moving
/// provenance recording out of the per-block closure -- it stays
/// exactly where it was, just no longer sharing that closure with a
/// provenance write.
#[tokio::test]
async fn successful_fetch_still_clears_a_stale_refusal() {
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b).await;

    let path = "refusal-clear.bin";
    let content: &[u8] = b"clears-a-stale-refusal";
    let hash = seed_servable_block(&state_a, &store_a, content);
    seed_servable_record(&state_a, path, &[(hash.clone(), content.len())]);

    let record = record_for(path, &[(hash, content.len())]);
    let all_present = convergence_b
        .ensure_blocks_present(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            path,
            &record,
            &version_of(&record),
            TIMEOUT,
        )
        .await
        .unwrap();
    assert!(all_present);

    let calls = state_b.test_observers.clear_block_fetch_refusal_call_log();
    assert_eq!(
        calls.len(),
        1,
        "one successful fetch must still make exactly one clear_block_fetch_refusal call: \
         {calls:?}"
    );
    assert_eq!(calls[0].0, GROUP);
    assert_eq!(calls[0].1, path);
    assert_eq!(calls[0].3, "device-a", "the clear must be scoped to the peer that answered");
}

// --- Cross-file provenance batching (`ReconcileProvenanceBatch`) ----
//
// These exercise `prepare_ordinary_projected_upsert`/`try_commit_
// ordinary_batch` directly (both private, reachable here the same way
// `ordinary_batch_tests` above reaches them), since the cross-file
// batch boundary lives there, not in `ensure_blocks_present` itself.
// Unlike `ordinary_batch_tests`'s own harness (which always pre-seeds
// content AND provenance together, so its candidates never reach a
// real fetch at all), these need genuinely NEW fetches to exercise the
// batching -- so `prepare`'s `PathHead` is resolved from a REAL
// `Change` admitted into `state_b`'s own DAG (`combined_heads`/
// `revalidate_ordinary_upsert` both require one), while each block's
// CONTENT is only ever seeded on `state_a`/`store_a` (the servable
// side), forcing session_b to actually fetch it over the wire.

/// Admits a real DAG `Change` for `path` into `state_b` (mirroring
/// `ordinary_batch_tests::Harness::admit`'s own chaining discipline)
/// and resolves the resulting winning `PathHead`, exactly as
/// `reconcile_group_paths`'s own fixpoint would -- ready to hand to
/// `prepare_ordinary_projected_upsert`. `hash`/`content_len` describe
/// content that must already be servable by A (`seed_servable_block`/
/// `seed_servable_record`) but is deliberately NOT present on B.
async fn admit_and_resolve_head(
    convergence_b: &Arc<super::LocalConvergenceExecutor>,
    state_b: &ReplicaCoordinator,
    sender_db: &rusqlite::Connection,
    emitter: &ChangeEmitter,
    path: &str,
    hash: Vec<u8>,
    content_len: usize,
) -> PathHead {
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(hash), size: content_len as u32 }],
        content_len as u64,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let change = dag_store::emit_local_change(
        sender_db,
        GROUP,
        vec![Op::Put {
            path: SyncPath(path.to_string()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        emitter,
    )
    .unwrap();
    // Distinct per change: the real store refuses two different payloads
    // under one checkpoint hash, and the payload names the author.
    let evidence = yadorilink_replica_engine::ports::ChangeEvidence {
        checkpoint_hash: change.compute_hash().0,
        checkpoint_seq: 0,
        checkpoint_encoded: Vec::new(),
        checkpoint_signature: Vec::new(),
        author_signing_public_key: [0u8; 32],
        merkle_proof_encoded: Vec::new(),
    };
    state_b
        .change_history_repository()
        .dag_admit_change_batch_with_versions(&[yadorilink_sync_sqlite::PendingAdmission {
            change: &change,
            versions: std::slice::from_ref(&version),
            evidence: Some(&evidence),
        }])
        .remove(0)
        .unwrap();
    let heads = convergence_b.combined_heads(GROUP, path, None).unwrap();
    match resolve_path_heads(path, &heads) {
        PathResolution::Present { winner, .. } => heads[winner].clone(),
        PathResolution::Absent => {
            panic!("{path}: expected a live content head after admission")
        }
    }
}

/// Everything a pass obtains is recorded in ONE provenance transaction.
///
/// This property used to belong to the commit boundary, because
/// preparation fetched each candidate's blocks itself and the flush was
/// deferred to batch them back together. Content acquisition now happens
/// once, before the pass, so the batching is no longer a recovery from
/// per-file fetching -- it is simply where the work is. The property is
/// the same one, on the chokepoint it moved to: eight files must not cost
/// eight transactions.
#[tokio::test]
async fn everything_a_pass_obtains_is_recorded_in_one_transaction() {
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b).await;
    let sender_db = rusqlite::Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender_db).unwrap();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[66u8; 32]));

    let mut paths = std::collections::BTreeSet::new();
    for i in 0..8 {
        let path = format!("one-batch-{i}.bin");
        let content = format!("content for one-batch file {i}").into_bytes();
        let hash = seed_servable_block(&state_a, &store_a, &content);
        seed_servable_record(&state_a, &path, &[(hash.clone(), content.len())]);
        admit_and_resolve_head(
            &convergence_b,
            &state_b,
            &sender_db,
            &emitter,
            &path,
            hash,
            content.len(),
        )
        .await;
        paths.insert(path);
    }

    let obtained = convergence_b
        .obtain_missing_content(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            &paths,
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();
    assert_eq!(obtained.len(), 8, "every path's content was missing, so every one was asked for");

    let batches = state_b.test_observers.provenance_batches();
    assert_eq!(
        batches.len(),
        1,
        "eight files obtained in one pass must cost one provenance transaction, not one \
         each: {batches:?}"
    );
    assert_eq!(batches[0].len(), 8, "and that transaction carries all eight hashes");
}

/// The attempt's own timer must see the blocks the attempt fetched.
///
/// An attempt obtains its content in `obtain_missing_content`, which
/// runs strictly BEFORE `reconcile_group_paths` is entered. While that
/// inner function constructed the timer it reports from, every
/// block-fetch counter on the reported line was structurally pinned at
/// zero on this path -- the fetching had already finished, into a
/// different, discarded timer. A real two-device run made the
/// consequence concrete: 13,340 genuine block round trips, every one of
/// them reported as `blocks_fetched=0 block_fetch_wait_ms=0`, which is
/// exactly the kind of silently-wrong measurement that misdirects a
/// diagnosis.
///
/// Asserting on the timer the attempt itself was handed (rather than on
/// a second one built the same way) is the whole point: the defect was
/// never that the numbers could not be recorded, only that they were
/// recorded somewhere nothing reports.
#[tokio::test]
async fn an_attempts_own_timer_records_the_blocks_that_attempt_fetched() {
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let (_session_a, state_a, store_a, session_b, _state_b, convergence_b) =
        connected_pair(store_b).await;
    let sender_db = rusqlite::Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender_db).unwrap();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[66u8; 32]));

    let path = "timer-sees-this.bin";
    let content = b"content that has to travel over the wire to get here".to_vec();
    let hash = seed_servable_block(&state_a, &store_a, &content);
    seed_servable_record(&state_a, path, &[(hash.clone(), content.len())]);
    admit_and_resolve_head(
        &convergence_b,
        &_state_b,
        &sender_db,
        &emitter,
        path,
        hash,
        content.len(),
    )
    .await;

    // The very timer the attempt reports from -- injected, not a copy.
    let call_timer = crate::local_convergence::call_timer::ReconcileCallTimer::new();
    let attempt = convergence_b
        .reconcile_paths_directly_with_timer(
            &(session_b.clone()
                as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>),
            GROUP,
            std::collections::BTreeSet::from([path.to_string()]),
            &call_timer,
        )
        .await
        .unwrap();
    assert!(
        attempt.is_some(),
        "sanity: the attempt must have actually run, not been skipped by the link gate or \
         the audit guard -- a skipped attempt fetches nothing and would pass the real \
         assertions below vacuously"
    );

    assert!(
        call_timer.blocks_fetched() > 0,
        "the attempt fetched this path's only block over the wire, so its own timer must \
         have counted it; blocks_fetched=0 means the fetch was recorded into a timer \
         nothing reports"
    );
    assert!(
        call_timer.block_fetch_wait_ns() > 0,
        "and the requester-observed wire wait for that fetch must land on the same timer"
    );
    assert!(
        call_timer.store_put_ns() > 0,
        "as must the durable store.put that followed it -- the three counters that \
         together describe where an attempt's block time actually goes"
    );
}

/// Missing-block regression: a block the requester needs but the peer
/// cannot actually produce (provenanced/referenced, but never stored --
/// the peer's own `FileRecord` names a correct block hash that was never
/// fetched into its store) must never
/// advance the requester's `materialization_state` to `Hydrated`, and
/// once the peer genuinely has the block, the SAME path must reach
/// `Hydrated` with byte-identical content. This test pins that
/// invariant so it cannot regress silently.
#[tokio::test]
async fn a_block_the_peer_cannot_produce_never_advances_past_placeholder() {
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b).await;
    let sender_db = rusqlite::Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender_db).unwrap();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[66u8; 32]));

    let path = "never-served-then-served.bin";
    let content = b"the peer will claim this block exists before it actually does".to_vec();

    // Learn the real content hash without ever putting the bytes into
    // A's own store -- a throwaway store only used to compute the same
    // hash A's real store would derive, so A can reference a hash it
    // genuinely does not yet hold.
    let scratch_store = SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap();
    let hash = hex::decode(scratch_store.put(&content).unwrap()).unwrap();

    // A references and provenances the block (the metadata gate real
    // `handle_block_request` checks first) without ever storing its
    // bytes (the content gate it checks second) -- exactly the split
    // `file_0001.txt` was found in: a correct `FileRecord` naming a
    // block the CAS never received.
    state_a
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash))
        .unwrap();
    seed_servable_record(&state_a, path, &[(hash.clone(), content.len())]);
    admit_and_resolve_head(
        &convergence_b,
        &state_b,
        &sender_db,
        &emitter,
        path,
        hash.clone(),
        content.len(),
    )
    .await;

    // First attempt: A cannot actually produce the block. This must be
    // an ordinary retriable outcome, not a promotion to `Hydrated`.
    let _ = convergence_b
        .reconcile_paths_directly(
            &(session_b.clone()
                as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>),
            GROUP,
            std::collections::BTreeSet::from([path.to_string()]),
        )
        .await
        .unwrap();
    assert_ne!(
        state_b.get_materialization_state(GROUP, path).unwrap(),
        Some(MaterializationState::Hydrated),
        "a block the peer referenced but never stored must never advance this path to \
         Hydrated -- doing so would be a silent-corruption shape"
    );

    // Now the peer genuinely has it -- the same path must converge to
    // Hydrated with byte-identical content once a real fetch can
    // succeed.
    store_a.put(&content).unwrap();
    let attempt = convergence_b
        .reconcile_paths_directly(
            &(session_b.clone()
                as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>),
            GROUP,
            std::collections::BTreeSet::from([path.to_string()]),
        )
        .await
        .unwrap();
    assert!(attempt.is_some(), "sanity: the recovery attempt must actually have run");
    assert_eq!(
        state_b.get_materialization_state(GROUP, path).unwrap(),
        Some(MaterializationState::Hydrated),
        "once the peer can actually produce the block, the same path must reach Hydrated"
    );
}

/// Many one-block FILES share a handful of durability barriers.
///
/// This is the measurement the storage rewrite was actually for, and
/// the one a per-file commit pool could never satisfy. A tiny-file
/// workload is exactly one block per file, so batching within a file
/// has nothing to batch: a real two-daemon run of 2000 such files
/// produced 2001 blocks and 2001 barriers, one per block, with the
/// block store's group commit unable to help because the caller handed
/// it one block at a time.
///
/// The bound is loose on purpose. `RECEIVE_COMMIT_BATCH_BLOCKS` is 256
/// and the pass drains once at the end, so 40 files should fit in a
/// single batch -- but asserting exactly 1 would be asserting that no
/// other block store activity in this fixture ever takes a barrier,
/// which is not this test's claim. What it does catch is the
/// regression that matters: a return to per-file (and so, here,
/// per-block) commits would read 40, not 3.
#[tokio::test]
async fn many_one_block_files_share_a_barrier() {
    const FILES: usize = 40;

    let concrete = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let barriers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&barriers);
    concrete.install_durability_barrier_hook_for_tests(move || {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> = concrete;
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b.clone()).await;

    let sender_db = rusqlite::Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender_db).unwrap();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[66u8; 32]));

    let mut paths = std::collections::BTreeSet::new();
    let mut hashes = Vec::new();
    for i in 0..FILES {
        // Distinct content per file: identical bytes would dedup to one
        // hash and quietly turn this into a one-block test.
        let content = format!("one-block-file-number-{i:04}").into_bytes();
        let hash = seed_servable_block(&state_a, &store_a, &content);
        let path = format!("tiny-{i:04}.bin");
        seed_servable_record(&state_a, &path, &[(hash.clone(), content.len())]);
        admit_and_resolve_head(
            &convergence_b,
            &state_b,
            &sender_db,
            &emitter,
            &path,
            hash.clone(),
            content.len(),
        )
        .await;
        paths.insert(path);
        hashes.push(hash);
    }

    let before = barriers.load(std::sync::atomic::Ordering::Relaxed);
    convergence_b
        .obtain_missing_content(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            &paths,
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();
    let observed = barriers.load(std::sync::atomic::Ordering::Relaxed) - before;

    assert!(
        observed <= 3,
        "{FILES} one-block files must share a handful of barriers, not take one each -- \
         observed {observed}"
    );
    assert!(observed >= 1, "the blocks must actually have been committed");

    // The barrier saving must not have cost correctness: every block is
    // genuinely readable back, and provenance names all of them.
    let recorded: Vec<_> =
        state_b.test_observers.provenance_batches().into_iter().flatten().collect();
    for hash in &hashes {
        let hex_hash = hex::encode(hash);
        assert!(
            yadorilink_peer_session::ports::BlockContentStore::get(store_b.as_ref(), &hex_hash)
                .is_ok(),
            "block {hex_hash} was not readable from the receiver's own store"
        );
        assert!(
            recorded.contains(hash),
            "every durably committed block must be provenanced: {hex_hash}"
        );
    }
}

/// A block two files share is obtained once, not once per file.
#[tokio::test]
async fn a_block_two_files_share_is_obtained_once() {
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b).await;
    let sender_db = rusqlite::Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender_db).unwrap();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[66u8; 32]));

    let content = b"the identical bytes both files are made of".to_vec();
    let hash = seed_servable_block(&state_a, &store_a, &content);
    let mut paths = std::collections::BTreeSet::new();
    for path in ["shared-a.bin", "shared-b.bin"] {
        seed_servable_record(&state_a, path, &[(hash.clone(), content.len())]);
        admit_and_resolve_head(
            &convergence_b,
            &state_b,
            &sender_db,
            &emitter,
            path,
            hash.clone(),
            content.len(),
        )
        .await;
        paths.insert(path.to_string());
    }

    convergence_b
        .obtain_missing_content(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            &paths,
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    let batches = state_b.test_observers.provenance_batches();
    let recorded: Vec<_> = batches.iter().flatten().collect();
    assert_eq!(
        recorded.len(),
        1,
        "the second file must find the block already obtained by the first, still queued \
         behind this pass's single flush: {batches:?}"
    );
}

/// A durability commit that fails provenances nothing it carried --
/// including a sibling file's block that would have stored cleanly on
/// its own.
///
/// This is the deliberate trade of pooling commits ACROSS files, and it
/// changed when that pooling landed. Before, each file committed
/// separately, so one file's store failure left its siblings durable
/// and provenanced. Now a batch spans files and is all-or-nothing, so a
/// store error loses everything in that batch. Asserting the old
/// sibling-survives behaviour would now be asserting a defect: the
/// sibling's bytes are not on disk, and provenance claiming otherwise
/// is precisely the "claimed as held but absent" state the whole
/// ordering contract exists to prevent.
///
/// What is given up is re-fetching up to `RECEIVE_COMMIT_BATCH_BLOCKS`
/// blocks on a later pass. What is kept is the invariant, and the
/// barrier collapse that motivated the pooling -- a per-file commit
/// cannot batch a one-block-per-file workload at all. A store error
/// here is also systemic rather than per-block (ENOSPC, I/O), so the
/// batch that retried those blocks individually would very likely fail
/// on each of them anyway.
#[tokio::test]
async fn a_failed_commit_provenances_nothing_it_carried() {
    let inner = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let store_b = FailingBlockStore::new(inner);
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b.clone()).await;
    let sender_db = rusqlite::Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender_db).unwrap();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[66u8; 32]));

    let good_content = b"the sibling that stores cleanly".to_vec();
    let good_hash = seed_servable_block(&state_a, &store_a, &good_content);
    seed_servable_record(&state_a, "good.bin", &[(good_hash.clone(), good_content.len())]);
    admit_and_resolve_head(
        &convergence_b,
        &state_b,
        &sender_db,
        &emitter,
        "good.bin",
        good_hash.clone(),
        good_content.len(),
    )
    .await;

    let bad_content = b"the file whose store.put is made to fail".to_vec();
    let bad_hash = seed_servable_block(&state_a, &store_a, &bad_content);
    seed_servable_record(&state_a, "bad.bin", &[(bad_hash.clone(), bad_content.len())]);
    admit_and_resolve_head(
        &convergence_b,
        &state_b,
        &sender_db,
        &emitter,
        "bad.bin",
        bad_hash.clone(),
        bad_content.len(),
    )
    .await;
    store_b.fail_next_put_of(&bad_content);

    let paths = std::collections::BTreeSet::from(["bad.bin".to_string(), "good.bin".to_string()]);
    // The pass itself does not fail: a file whose content could not be
    // stored is absent, which the pass records durably and retries.
    convergence_b
        .obtain_missing_content(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            &paths,
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await
        .unwrap();

    let recorded: Vec<_> =
        state_b.test_observers.provenance_batches().into_iter().flatten().collect();
    assert!(
        !recorded.contains(&bad_hash),
        "a block that never reached the store must never be claimed as held: {recorded:?}"
    );
    assert!(
        !recorded.contains(&good_hash),
        "the sibling shared the failed batch, so its bytes are not on disk either and it \
         must not be provenanced: {recorded:?}"
    );
    // The invariant itself, checked against the store rather than
    // inferred from which blocks were expected to survive: every hash
    // that reached provenance names a block this device actually holds.
    for hash in &recorded {
        let hex_hash = hex::encode(hash);
        assert!(
            yadorilink_peer_session::ports::BlockContentStore::get(store_b.as_ref(), &hex_hash)
                .is_ok(),
            "provenance was recorded for {hex_hash}, which the block store does not hold"
        );
    }
}

/// A provenance transaction that fails takes the whole pass with it.
///
/// Fail-closed, and the ordering that makes it safe: nothing this pass
/// obtained is published until this group can prove it holds the blocks.
/// A pass that cannot record that proof must publish nothing at all.
#[tokio::test]
async fn a_failed_provenance_transaction_fails_the_whole_pass() {
    let store_b: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let (_session_a, state_a, store_a, session_b, state_b, convergence_b) =
        connected_pair(store_b).await;
    let sender_db = rusqlite::Connection::open_in_memory().unwrap();
    dag_store::init_dag_schema(&sender_db).unwrap();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[66u8; 32]));

    let mut paths = std::collections::BTreeSet::new();
    for i in 0..3 {
        let path = format!("flush-fails-{i}.bin");
        let content = format!("content for flush-fails file {i}").into_bytes();
        let hash = seed_servable_block(&state_a, &store_a, &content);
        seed_servable_record(&state_a, &path, &[(hash.clone(), content.len())]);
        admit_and_resolve_head(
            &convergence_b,
            &state_b,
            &sender_db,
            &emitter,
            &path,
            hash,
            content.len(),
        )
        .await;
        paths.insert(path);
    }

    // Every block is genuinely, durably fetched first; the SQL write is
    // what fails. That is the distinction this test exists for.
    state_b
        .test_observers
        .record_group_block_provenance_fails
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let result = convergence_b
        .obtain_missing_content(
            &(session_b.clone()
                as std::sync::Arc<
                    dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver,
                >),
            GROUP,
            &paths,
            &crate::local_convergence::call_timer::ReconcileCallTimer::new(),
        )
        .await;
    assert!(
        result.is_err(),
        "a pass that cannot record what it obtained must fail rather than let the paths that \
         depend on that proof publish: {result:?}"
    );
}
