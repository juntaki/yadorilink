//! R3d/R3e: focused regression for the root cause behind R3c's 168/168
//! `FETCH_RESPONSE_TIMEOUT` failures during `relay_failure_during_
//! hydration`'s recovery step -- NOT a reconnect-churn or transport-
//! lifecycle bug (both were ruled out: the post-recovery relay generation
//! is stable, and a single lane through it succeeds in 1-3s). The actual
//! cause: several concurrent block fetches sharing ONE relay-forwarded
//! connection measurably do not get anywhere near that connection's
//! nominal bandwidth each -- 8 concurrent 128KiB fetches needed 13.3-14.3s
//! each to complete once actually given room to -- so the OLD fixed 5s
//! `FETCH_RESPONSE_TIMEOUT` was aborting genuinely still-progressing
//! fetches before they could finish. Nothing upstream of that deadline was
//! found dropping packets (`RelayForwarder`'s own recv loop, this device's
//! outbound control-channel queue, and quinn's own inbound datagram queue
//! were all instrumented during the investigation and showed zero drops).
//!
//! Fixed by sizing the per-block response deadline to the block's own
//! declared size (`PeerSyncSession::fetch_response_timeout_for`,
//! `hydration::per_block_fetch_timeout`) instead of one fixed constant --
//! see those functions' own doc comments for the measurement and formula.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{
    snapshot_relay_recovery, stand_up_relay_forced_topology, wait_for_new_stable_relay_generation,
    wire_relay_grant_source_with_ttl,
};

// See `topology_simultaneous_reconnect_and_relay_hydration_failure.rs`'s
// own comment on this same constant: 300s was enough before the size-aware
// per-block deadline fix, but a single `hydrate_with_retries`-style
// sequence can now approach that boundary. This file's own fixture doesn't
// retry hydrate, but shares the same revoke/restore/stabilize setup, so
// keep the same generous margin for consistency.
const RELAY_GRANT_TTL_SECONDS: i64 = 900;

/// Fetches each of `blocks` (hash, declared size) concurrently over
/// `session`, one lane per block, bounded by `lane_timeout`. Uses
/// `fetch_block_sized` (not the size-agnostic `fetch_block`) -- matching
/// real hydration dispatch, which always knows a block's declared size
/// from its `FileRecord` and sizes its own per-block deadline from it (see
/// `PeerSyncSession::fetch_response_timeout_for`'s own doc comment).
/// Returns `(elapsed, succeeded)` per lane, in completion order.
async fn fetch_concurrently(
    session: &Arc<yadorilink_peer_session::peer_session::PeerSyncSession>,
    group_id: &str,
    path: &str,
    blocks: &[(Vec<u8>, u64)],
    lane_timeout: Duration,
) -> Vec<(Duration, bool)> {
    let mut tasks = tokio::task::JoinSet::new();
    for (hash, size) in blocks.iter().cloned() {
        let session = session.clone();
        let group_id = group_id.to_string();
        let path = path.to_string();
        tasks.spawn(async move {
            let started = std::time::Instant::now();
            let result = tokio::time::timeout(
                lane_timeout,
                session.fetch_block_sized(&group_id, &path, &hash, size),
            )
            .await;
            (started.elapsed(), matches!(result, Ok(Ok(Some(_)))))
        });
    }
    let mut results = Vec::with_capacity(blocks.len());
    while let Some(joined) = tasks.join_next().await {
        results.push(joined.expect("fetch task must not panic"));
    }
    results
}

/// Stands up the relay-forced topology, gives M and W a long grant TTL
/// (this test's own pacing has nothing to do with grant expiry -- see
/// `wire_relay_grant_source_with_ttl`'s own doc comment), authors an
/// 8-plus-block file on M, and drives the SAME revoke/restore/stabilize
/// cycle `relay_failure_during_hydration` does -- so the returned session
/// is the exact "post-recovery" relay generation the original 168/168
/// failures were observed on, not merely "a relay session."
async fn stand_up_post_recovery_relay_fixture() -> (
    support::topology::TopologyNode,
    support::topology::TopologyNode,
    support::topology::TopologyNode,
    support::topology::TopologyHandles,
    String,
    Vec<(Vec<u8>, u64)>,
) {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    let group_id = "relay-concurrent-fetch-regression-group".to_string();
    let (n, m, w, handles) = stand_up_relay_forced_topology(&fake, &group_id).await;
    wire_relay_grant_source_with_ttl(&fake, &m.state, &m.device_id, RELAY_GRANT_TTL_SECONDS);
    wire_relay_grant_source_with_ttl(&fake, &w.state, &w.device_id, RELAY_GRANT_TTL_SECONDS);

    let payload = {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5233_4400_1122_3344);
        // ~16 blocks at the default 128KiB chunk size -- enough to pick 8
        // distinct blocks for the concurrent-lane cases, matching real
        // hydration dispatch (fetch_window=4 per candidate x 2 candidates).
        let mut bytes = vec![0u8; 2 * 1024 * 1024];
        rng.fill_bytes(&mut bytes);
        bytes
    };
    std::fs::write(m.root.path().join("target.bin"), &payload).unwrap();
    support::wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .list_files(&group_id)
                .map(|files| {
                    files
                        .iter()
                        .any(|f| f.path == "target.bin" && !f.deleted && !f.blocks.is_empty())
                })
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || "W never saw the DAG record for target.bin".to_string(),
    )
    .await;
    let record = w
        .state
        .replica_coordinator
        .file_index_repository()
        .list_files(&group_id)
        .unwrap()
        .into_iter()
        .find(|f| f.path == "target.bin")
        .unwrap();
    assert!(record.blocks.len() >= 8, "need >= 8 distinct blocks for the concurrent-lane cases");

    let before_revoke =
        snapshot_relay_recovery(&n.state, &m.state, &w.state, &m.device_id, &w.device_id);
    fake.set_relay_capable(&n.device_id, false);
    n.state.set_local_relay_capable(false);
    tokio::time::sleep(Duration::from_millis(500)).await;
    fake.set_relay_capable(&n.device_id, true);
    n.state.set_local_relay_capable(true);
    wait_for_new_stable_relay_generation(
        &n.state,
        &m.state,
        &w.state,
        &m.device_id,
        &w.device_id,
        &before_revoke,
        Duration::from_secs(90),
    )
    .await;

    let blocks: Vec<(Vec<u8>, u64)> =
        record.blocks[..8].iter().map(|b| (b.hash.clone(), b.size as u64)).collect();
    (n, m, w, handles, group_id, blocks)
}

/// The core regression: 8 concurrent block fetches sharing one post-
/// recovery relay session must all eventually succeed. Before the size-
/// aware timeout fix, this was 0/8 (every lane hit the fixed 5s `FETCH_
/// RESPONSE_TIMEOUT` with no reply, despite real relay traffic flowing).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn eight_concurrent_lanes_through_a_relay_session_all_succeed() {
    let (_n, m, w, handles, group_id, blocks) = stand_up_post_recovery_relay_fixture().await;
    let session_to_m = w.state.peers.session(&m.device_id).expect("W must have a session to M");

    // Generous relative to the measured worst case (13.3-14.3s) without
    // being unbounded -- a regression here should fail loudly, not hang.
    let results = fetch_concurrently(
        &session_to_m,
        &group_id,
        "target.bin",
        &blocks,
        Duration::from_secs(45),
    )
    .await;

    let failures: Vec<_> = results.iter().filter(|(_, succeeded)| !succeeded).collect();
    assert!(
        failures.is_empty(),
        "all 8 concurrent lanes through the relay session must succeed; {} of {} failed: {results:?}",
        failures.len(),
        results.len(),
    );

    handles.shutdown();
}

/// Control: the SAME 8-concurrent-lane shape, direct (non-relayed) to N,
/// must succeed fast (well under a second) -- proving concurrency itself
/// is not the issue, and this fix did not weaken direct-path timing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn eight_concurrent_lanes_direct_succeed_fast() {
    let (n, _m, w, handles, group_id, _) = stand_up_post_recovery_relay_fixture().await;

    let n_payload = {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x4e4f_574e_4544_4247);
        let mut bytes = vec![0u8; 2 * 1024 * 1024];
        rng.fill_bytes(&mut bytes);
        bytes
    };
    std::fs::write(n.root.path().join("n-owned.bin"), &n_payload).unwrap();
    support::wait_until_with_context(
        || {
            n.state
                .replica_coordinator
                .file_index_repository()
                .list_files(&group_id)
                .map(|files| {
                    files
                        .iter()
                        .any(|f| f.path == "n-owned.bin" && !f.deleted && !f.blocks.is_empty())
                })
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || "N never indexed its own n-owned.bin".to_string(),
    )
    .await;
    let n_record = n
        .state
        .replica_coordinator
        .file_index_repository()
        .list_files(&group_id)
        .unwrap()
        .into_iter()
        .find(|f| f.path == "n-owned.bin")
        .unwrap();
    assert!(n_record.blocks.len() >= 8, "need >= 8 distinct N-owned blocks");
    let n_blocks: Vec<(Vec<u8>, u64)> =
        n_record.blocks[..8].iter().map(|b| (b.hash.clone(), b.size as u64)).collect();

    let session_to_n = w.state.peers.session(&n.device_id).expect("W must have a session to N");
    let started = std::time::Instant::now();
    let results = fetch_concurrently(
        &session_to_n,
        &group_id,
        "n-owned.bin",
        &n_blocks,
        Duration::from_secs(10),
    )
    .await;
    let elapsed = started.elapsed();

    let failures: Vec<_> = results.iter().filter(|(_, succeeded)| !succeeded).collect();
    assert!(failures.is_empty(), "all 8 concurrent DIRECT lanes must succeed: {results:?}");
    assert!(
        elapsed < Duration::from_secs(5),
        "8 concurrent DIRECT lanes must complete fast (no relay contention involved); took {elapsed:?}"
    );

    handles.shutdown();
}
