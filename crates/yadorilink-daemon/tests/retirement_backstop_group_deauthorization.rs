//! Regression coverage for a bug found investigating a real 10 GiB
//! `large_file_transfer_bench.rs` `HydrationFailed` failure: `DaemonState::new`
//! always starts the convergence engine's background tasks
//! (`maintenance_coordinator::start` -> `convergence::engine::run`), which
//! include an ephemeral-conflict-copy retirement loop with a periodic
//! backstop (`RETIREMENT_BACKSTOP_INTERVAL`, `convergence/engine_wrapper.rs`
//! -- currently 30s). `DaemonState::local_retirement_session` caches its
//! constructed synthetic session per group, so the one thing that actually
//! revokes authorization -- `NetmapChangeAuthenticator::new`'s
//! (`change_auth.rs`) eager `validate_linked_history_best_effort` ->
//! `restore_group_sessions_if_currently_authorized` -- only ever runs ONCE
//! per group per process, on the first retirement pass that reaches that
//! group (here, the backstop's first tick, since nothing else marks the
//! group dirty). A group with no verified `GroupPolicyState` and no
//! netmap-confirmed writer is deauthorized on every currently-registered
//! peer session on that one pass -- and because the check never runs again
//! for that group, the deauthorization is PERMANENT for the rest of the
//! process, not something a later tick could self-heal.
//!
//! A daemon integration test that constructs a real `DaemonState`, links a
//! group, and registers a `PeerSyncSession` by hand -- bypassing the signed
//! Change/DAG admission path and netmap wiring a real device always has --
//! never satisfies either condition. That is harmless as long as the whole
//! test finishes well inside 30s (every pre-existing test using this wiring
//! pattern always has). `large_file_transfer_bench.rs`'s 10 GiB tier does
//! not: real content-defined chunking of a file that size can itself take
//! well over 30s, so the backstop's one-shot check fires (and permanently
//! deauthorizes the destination's session) before `hydration::hydrate()` is
//! ever called -- every retry then fails fast with `HydrationFailed`, never
//! fetching a single block. Not a hydration bug: `hydration.rs`'s
//! block-fetch path worked exactly as designed once given an authorized
//! candidate session.
//!
//! This reproduces the same mechanism deterministically without needing
//! gigabytes of data: a tiny single-block file, real two-device QUIC
//! session wiring (the same pattern `perf_regression.rs`/
//! `large_file_transfer_bench.rs` use), and an explicit wait past the
//! backstop interval before the first `hydrate()` attempt -- standing in for
//! "chunking took a long time" without actually chunking anything large.
//! The wait is derived from `convergence::engine::retirement_backstop_
//! interval_for_tests()` rather than a hardcoded duplicate of
//! `RETIREMENT_BACKSTOP_INTERVAL`, plus an assertion that a backstop tick
//! was actually observed pre-`hydrate()` (`retirement_backstop_ticked`
//! below) -- so if that interval is ever retuned longer, this test fails
//! loudly (it stops observing a tick within its own wait) instead of
//! silently passing without ever exercising the regression again.
//!
//! `DaemonState::install_test_group_policy_bootstrap` plus
//! `DaemonState::set_peer_group_writer` are the fix under test: without
//! them, this test fails with `HydrationFailed` after every retry (verified
//! live by temporarily removing both calls below); with them, the
//! destination's session survives the backstop tick and hydration succeeds
//! on its first real attempt.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_daemon::convergence::engine::retirement_backstop_interval_for_tests;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::hydration;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::{chunk_file, FsBlockStore};
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_transport::{
    ConnectRole, DeviceSigningKeyPair, QuicPeerChannel, QuicPeerEndpoint, TransportHub,
};

const GROUP: &str = "retirement-backstop-repro-group";

/// Margin added atop the real `RETIREMENT_BACKSTOP_INTERVAL` (fetched via
/// `retirement_backstop_interval_for_tests()`, not duplicated as a
/// hardcoded constant here) before the first `hydrate()` attempt -- room
/// for scheduling jitter on a loaded runner, not a guess at the interval
/// itself. If that interval is ever retuned, this test's wait tracks it
/// automatically; `retirement_backstop_ticked` below is the independent
/// check that the wait was actually long enough in practice.
const BACKSTOP_WAIT_MARGIN: Duration = Duration::from_secs(5);

/// Polls `state.has_local_retirement_session(group_id)` until it becomes
/// true or `deadline` passes -- the fix-independent signal that the
/// retirement backstop's one-shot authorization check has actually run for
/// this group (see this file's own module doc comment), as opposed to just
/// having waited long enough on the assumption that it would.
async fn retirement_backstop_ticked(
    state: &DaemonState,
    group_id: &str,
    deadline: Duration,
) -> bool {
    let started = tokio::time::Instant::now();
    while started.elapsed() < deadline {
        if state.has_local_retirement_session(group_id) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    state.has_local_retirement_session(group_id)
}

fn tiny_content() -> Vec<u8> {
    b"retirement backstop deauthorization regression payload".to_vec()
}

#[ignore = "real-time regression test (~35-40s unconditional wait past the retirement backstop interval) -- run explicitly with --ignored, not in ordinary CI"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manually_registered_session_survives_the_retirement_backstop() {
    let content = tiny_content();
    let source_dir = tempfile::tempdir().unwrap();
    let source_store = Arc::new(FsBlockStore::new(source_dir.path()).unwrap());
    let blocks = {
        let tmp_file = source_dir.path().join("source.bin");
        std::fs::write(&tmp_file, &content).unwrap();
        chunk_file(source_store.as_ref(), &tmp_file).unwrap()
    };

    let dest_dir = tempfile::tempdir().unwrap();
    let dest_store = Arc::new(FsBlockStore::new(dest_dir.path()).unwrap());
    let dest_sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let dest_root = tempfile::tempdir().unwrap();
    dest_sync_state.link_repository().add_link(&dest_root.path().to_string_lossy(), GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        dest_root.path(),
        GROUP,
        dest_sync_state.as_ref(),
    )
    .unwrap();
    dest_sync_state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "tiny.bin".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: blocks.clone(),
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    dest_sync_state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "tiny.bin",
            MaterializationState::Placeholder,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let dest_state = DaemonState::new("device-dest".into(), dest_sync_state.clone(), dest_store);
    dest_state.install_test_root_commit_authority(GROUP);
    // The fix under test -- see this file's own module doc comment. Comment
    // out these two lines to reproduce the pre-fix `HydrationFailed`.
    dest_state.install_test_group_policy_bootstrap(GROUP);
    dest_state.set_peer_group_writer("device-source", GROUP, true);

    let socket_source = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_dest = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_dest = socket_dest.local_addr().unwrap();

    let key_source = DeviceSigningKeyPair::generate();
    let key_dest = DeviceSigningKeyPair::generate();
    let public_source = key_source.public_bytes();
    let public_dest = key_dest.public_bytes();
    let endpoint_source =
        QuicPeerEndpoint::new(TransportHub::from_socket(socket_source), key_source).unwrap();
    let endpoint_dest =
        QuicPeerEndpoint::new(TransportHub::from_socket(socket_dest), key_dest).unwrap();
    endpoint_source.authorize(public_dest);
    endpoint_dest.authorize(public_source);
    let accepting = {
        let endpoint_dest = endpoint_dest.clone();
        tokio::spawn(async move { endpoint_dest.accept(public_source).await })
    };
    let dialed = endpoint_source.connect(addr_dest, public_dest).await.unwrap();
    let accepted = accepting.await.unwrap().unwrap();
    let channel_source = QuicPeerChannel::new(dialed, ConnectRole::Dial);
    let channel_dest = QuicPeerChannel::new(accepted, ConnectRole::Accept);

    let source_sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    source_sync_state
        .link_repository()
        .add_link(&source_dir.path().to_string_lossy(), GROUP)
        .unwrap();
    let source_record =
        dest_sync_state.file_index_repository().get_file(GROUP, "tiny.bin").unwrap().unwrap();
    source_sync_state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &source_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let block_hashes: Vec<Vec<u8>> = blocks.iter().map(|block| block.hash.clone()).collect();
    source_sync_state
        .change_history_repository()
        .record_group_block_provenance(GROUP, &block_hashes)
        .unwrap();
    let generation = source_sync_state.startup_readiness().begin_group_startup(GROUP);
    source_sync_state.startup_readiness().mark_group_ready(GROUP, generation);
    let session_source = PeerSyncSession::new(
        channel_source,
        "device-source".into(),
        "device-dest".into(),
        source_sync_state,
        source_store,
        vec![GROUP.to_string()],
        std::collections::HashMap::from([(GROUP.to_string(), source_dir.path().to_path_buf())]),
    );
    session_source.set_block_serve_engine(
        yadorilink_peer_session::block_serve::BlockServeEngine::new(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            1_000,
        ),
    );
    tokio::spawn(session_source.clone().run());

    let session_dest = PeerSyncSession::new(
        channel_dest,
        "device-dest".into(),
        "device-source".into(),
        dest_sync_state.clone(),
        std::sync::Arc::new(
            yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
                dest_state.block_store.clone(),
            ),
        ),
        vec![GROUP.to_string()],
        std::collections::HashMap::from([(GROUP.to_string(), dest_root.path().to_path_buf())]),
    );
    session_dest.set_block_serve_engine(dest_state.block_serve_engine.clone());
    tokio::spawn(session_dest.clone().run());
    dest_state.peers.register_session("device-source".into(), session_dest);

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Stand-in for "sender-side chunking took a long time": nothing about
    // this test's own work takes anywhere near this long, but the real 10
    // GiB repro's CDC chunking did -- long enough to let the retirement
    // loop's backstop tick fire (and, pre-fix, deauthorize the destination's
    // session) before `hydrate()` is ever attempted. Waits for the real
    // backstop interval (not a hardcoded duplicate) plus a scheduling
    // margin, THEN asserts the tick was actually observed -- see this
    // file's own module doc comment for why both matter.
    let backstop_deadline = retirement_backstop_interval_for_tests() + BACKSTOP_WAIT_MARGIN;
    assert!(
        retirement_backstop_ticked(&dest_state, GROUP, backstop_deadline).await,
        "retirement backstop never ticked for this group within {backstop_deadline:?} -- \
         this test no longer exercises the regression it exists to catch"
    );

    let mut hydrate_attempts = 0;
    loop {
        match hydration::hydrate(&dest_state, GROUP, "tiny.bin").await {
            Ok(()) => break,
            Err(e) if hydrate_attempts < 5 => {
                hydrate_attempts += 1;
                eprintln!("hydrate attempt {hydrate_attempts} failed ({e:?}), retrying...");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("hydrate never succeeded after {hydrate_attempts} retries: {e:?}"),
        }
    }

    assert_eq!(std::fs::read(dest_root.path().join("tiny.bin")).unwrap(), content);
}
