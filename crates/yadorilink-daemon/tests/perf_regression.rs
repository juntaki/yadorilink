//! Before/after-style regression coverage for
//! the two scenarios not already covered by a dedicated benchmark
//! in another crate — "large-file scan" and "large-file hydration" must
//! not block the tokio runtime (`link_manager.rs`'s `spawn_blocking`/
//! `block_in_place` wrapping, and `hydration.rs`'s `BlockStore::put`
//! `spawn_blocking` wrapping, respectively). The other two named
//! scenarios already have dedicated before/after
//! measurements elsewhere: "frequent-modify re-hash avoidance" in
//! `yadorilink-sync-core/src/local_change.rs`'s
//! `unchanged_size_and_mtime_skips_rechunking_entirely`, and
//! "full-index sync of many files" is exercised end-to-end by
//! `load_many_small_files.rs` (200 files through a real initial sync).
//!
//! The methodology here is deliberately "after-only, but proves the
//! actual claim" rather than a literal old-code-vs-new-code A/B: the old,
//! blocking code path no longer exists to compare against directly, so
//! instead of a wall-clock speed comparison, each test proves 's
//! real property directly — a large/expensive operation running
//! concurrently with a trivial async task must not delay that trivial
//! task, which is exactly what "don't block the tokio runtime" means in
//! practice and would reliably FAIL under the pre-code (a
//! multi-megabyte synchronous chunk/hash call occupying a worker thread
//! for its whole duration would delay a concurrent timer tick by a
//! similar order of magnitude).

use std::sync::Arc;
use std::time::{Duration, Instant};

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::hydration;
use yadorilink_daemon::link_manager;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::chunker::chunk_file;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::peer_session::PeerSyncSession;
use yadorilink_sync_core::types::{FileRecord, MaterializationState};
use yadorilink_sync_core::version_vector::VersionVector;
use yadorilink_transport::{PeerChannel, TransportHub};

const GROUP: &str = "perf-group";

async fn wait_until<F: Fn() -> bool>(cond: F, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition never became true within timeout"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A moderately large synthetic file (~20 MiB) — big enough that a
/// synchronous chunk/hash pass takes tens of milliseconds even on a fast
/// machine (long enough to reliably starve a concurrent timer tick if
/// nothing offloads it), without ballooning this test's own runtime or
/// disk footprint the way a genuinely multi-gigabyte file would. Only
/// used for the local-only scan test below — no network transport
/// involved, so block count doesn't matter here.
fn large_content() -> Vec<u8> {
    (0..(20 * 1024 * 1024)).map(|i| (i % 251) as u8).collect()
}

/// A smaller multi-block file (~1.5 MiB, ~12 blocks at the 128KiB
/// default block size) for the hydration test specifically — enough
/// blocks to be meaningfully "large" (several real network round trips,
/// not a single request), but deliberately far fewer than `large_content`'s
/// ~160 blocks would produce. Real, occasional transport-layer message
/// loss under load (a known, separately-diagnosed flakiness source in
/// this codebase's multi-peer hydration paths — each lost response costs
/// a `PER_BLOCK_FETCH_TIMEOUT` retry) compounds with block count: ~160
/// sequential/windowed round trips gave this test a meaningfully higher
/// chance of tripping the outer 30s `HYDRATION_TIMEOUT` under CI-level
/// contention than ~12 does, and this test's actual point (proving
/// `spawn_blocking` keeps the runtime responsive during hydration) needs
/// "more than one block," not "as many blocks as possible."
fn hydration_content() -> Vec<u8> {
    (0..(12 * 128 * 1024)).map(|i| (i % 251) as u8).collect()
}

/// (`link_manager.rs`'s wrapping of the initial `scan_existing_files`
/// call in `spawn_blocking`): scanning a large pre-existing file must not
/// delay an unrelated, concurrently-scheduled async task on the same
/// runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_file_scan_does_not_block_concurrent_async_work() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state.clone(), store);
    // A registered (non-empty device_id) DaemonState with no signing key
    // fails closed in `link_manager::build_change_processor` -- see that
    // function's own doc comment: without one, this device's local edits
    // would be indexed but never recorded as DAG changes, which is silent
    // data loss from the group's perspective, not a legitimate no-emitter
    // path.
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]));
    let root = tempfile::tempdir().unwrap();

    std::fs::write(root.path().join("large.bin"), large_content()).unwrap();
    sync_state.add_link(&root.path().to_string_lossy(), GROUP).unwrap();

    // A trivial, otherwise-unrelated timer task competing for the same
    // worker pool. If the large scan blocks a worker thread, this tick
    // (scheduled to fire almost immediately) gets delayed behind it.
    let tick_started = Instant::now();
    let tick_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5)).await;
        tick_started.elapsed()
    });

    link_manager::start_link_watch(
        state.clone(),
        root.path().to_string_lossy().into(),
        GROUP.into(),
    )
    .unwrap();

    let tick_delay = tokio::time::timeout(Duration::from_secs(10), tick_task)
        .await
        .expect("timer tick never completed — large scan appears to be blocking the runtime")
        .unwrap();

    // Generous bound (the tick itself only sleeps 5ms) — this isn't
    // measuring precise scheduling latency, just ruling out "blocked for
    // the whole multi-ten-millisecond scan duration."
    assert!(
        tick_delay < Duration::from_millis(500),
        "timer tick took {tick_delay:?} to complete — large file scan appears to be blocking a tokio worker thread"
    );

    wait_until(
        || sync_state.get_file(GROUP, "large.bin").ok().flatten().is_some(),
        Duration::from_secs(10),
    )
    .await;
    link_manager::stop_link_watch(&state, &root.path().to_string_lossy());
}

/// (`hydration.rs`'s `spawn_blocking` wrap around `BlockStore::put`
/// in `fetch_blocks_from_sessions`'s worker loop): hydrating a large file
/// must not delay an unrelated, concurrently-scheduled async task either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_file_hydration_does_not_block_concurrent_async_work() {
    let content = hydration_content();
    let source_dir = tempfile::tempdir().unwrap();
    let source_store = Arc::new(FsBlockStore::new(source_dir.path()).unwrap());
    let blocks = {
        let tmp_file = source_dir.path().join("source.bin");
        std::fs::write(&tmp_file, &content).unwrap();
        chunk_file(source_store.as_ref(), &tmp_file).unwrap()
    };
    assert!(blocks.len() > 4, "test needs a real multi-block file to be meaningful");

    let dest_dir = tempfile::tempdir().unwrap();
    let dest_store = Arc::new(FsBlockStore::new(dest_dir.path()).unwrap());
    let dest_sync_state = Arc::new(SyncState::open_in_memory().unwrap());
    let dest_root = tempfile::tempdir().unwrap();
    dest_sync_state.add_link(&dest_root.path().to_string_lossy(), GROUP).unwrap();
    let mut version = VersionVector::new();
    version.increment("device-source");
    dest_sync_state
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "large.bin".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                version,
                blocks: blocks.clone(),
                deleted: false,
            },
        )
        .unwrap();
    dest_sync_state
        .set_materialization_state(GROUP, "large.bin", MaterializationState::Placeholder)
        .unwrap();
    let dest_state = DaemonState::new("device-dest".into(), dest_sync_state.clone(), dest_store);

    let secret_source = boringtun::x25519::StaticSecret::from([61u8; 32]);
    let secret_dest = boringtun::x25519::StaticSecret::from([62u8; 32]);
    let public_source = boringtun::x25519::PublicKey::from(&secret_source);
    let public_dest = boringtun::x25519::PublicKey::from(&secret_dest);

    // Direct loopback pairing: each side binds a UDP socket and dials the
    // other's address as its sole direct candidate.
    let socket_source = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_dest = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_source = socket_source.local_addr().unwrap();
    let addr_dest = socket_dest.local_addr().unwrap();

    let channel_source = PeerChannel::connect(
        secret_source,
        public_dest,
        0,
        vec![addr_dest],
        TransportHub::from_socket(socket_source, None),
    )
    .await
    .unwrap();
    let channel_dest = PeerChannel::connect(
        secret_dest,
        public_source,
        1,
        vec![addr_source],
        TransportHub::from_socket(socket_dest, None),
    )
    .await
    .unwrap();

    // The serving side needs its own link for the group, exactly as the
    // receiving side has: sync roots are derived from the link table in
    // production (`sync_roots_for_groups` reads `list_links`), so a session
    // holding a root the link table does not know about is a state the daemon
    // cannot produce -- and the peer-apply path refuses it, which here would
    // stop this side ever learning (and so serving) the blocks under test.
    let source_sync_state = Arc::new(SyncState::open_in_memory().unwrap());
    source_sync_state.add_link(&source_dir.path().to_string_lossy(), GROUP).unwrap();
    let source_record = dest_sync_state.get_file(GROUP, "large.bin").unwrap().unwrap();
    source_sync_state.upsert_file(GROUP, &source_record).unwrap();
    // `chunk_file` above only writes these blocks into the source's own CAS
    // store -- it does not record group provenance for them, which the real
    // local-write path (`local_change.rs`) always does alongside a chunk
    // write. `handle_block_request`'s serving-authorization gate refuses any
    // block without it (`group_has_block_provenance`), so without this the
    // source would refuse every block request from the dest side as
    // not_found, and hydration would exhaust its retries and time out
    // instead of exercising the concurrent-async-work property under test.
    let block_hashes: Vec<Vec<u8>> = blocks.iter().map(|block| block.hash.clone()).collect();
    source_sync_state.record_group_block_provenance(GROUP, &block_hashes).unwrap();
    let generation = source_sync_state.begin_group_startup(GROUP);
    source_sync_state.mark_group_ready(GROUP, generation);
    let session_source = PeerSyncSession::new(
        Arc::new(channel_source),
        "device-source".into(),
        "device-dest".into(),
        source_sync_state,
        source_store,
        vec![GROUP.to_string()],
        std::collections::HashMap::from([(GROUP.to_string(), source_dir.path().to_path_buf())]),
    );
    tokio::spawn(session_source.clone().run());

    let session_dest = PeerSyncSession::new(
        Arc::new(channel_dest),
        "device-dest".into(),
        "device-source".into(),
        dest_sync_state.clone(),
        dest_state.block_store.clone(),
        vec![GROUP.to_string()],
        std::collections::HashMap::from([(GROUP.to_string(), dest_root.path().to_path_buf())]),
    );
    tokio::spawn(session_dest.clone().run());
    dest_state.sessions.lock().unwrap().insert("device-source".into(), session_dest);

    tokio::time::sleep(Duration::from_millis(200)).await;

    let tick_started = Instant::now();
    let tick_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5)).await;
        tick_started.elapsed()
    });

    let dest_state_arc = Arc::new(dest_state);
    // The 200ms sleep above is a head start, not a guarantee: the two
    // freshly-spawned PeerSyncSession::run tasks still need to complete
    // their own handshake with each other over the direct channel before
    // either is a usable hydration candidate, and that can occasionally
    // take longer than 200ms on a colder/more loaded runner than this was
    // tuned against (observed failing fast, in ~1s, on a first-ever
    // ubuntu-latest CI run -- nowhere near HYDRATION_TIMEOUT's 30s, i.e.
    // hydrate was correctly reporting "no candidate yet", not hanging).
    // Retrying tolerates that startup race without weakening what this
    // test actually verifies (that a real, in-progress hydration doesn't
    // block the runtime) -- once a hydration attempt gets far enough to
    // actually start fetching blocks, this loop's job is done.
    let mut hydrate_attempts = 0;
    loop {
        match hydration::hydrate(&dest_state_arc, GROUP, "large.bin").await {
            Ok(()) => break,
            Err(e) if hydrate_attempts < 10 => {
                hydrate_attempts += 1;
                eprintln!("hydrate attempt {hydrate_attempts} failed ({e:?}), retrying...");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("hydrate never succeeded after {hydrate_attempts} retries: {e:?}"),
        }
    }

    let tick_delay = tokio::time::timeout(Duration::from_secs(10), tick_task)
        .await
        .expect(
            "timer tick never completed — large file hydration appears to be blocking the runtime",
        )
        .unwrap();
    assert!(
        tick_delay < Duration::from_millis(500),
        "timer tick took {tick_delay:?} to complete — large file hydration appears to be blocking a tokio worker thread"
    );

    assert_eq!(std::fs::read(dest_root.path().join("large.bin")).unwrap(), content);
}
