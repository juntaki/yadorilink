//! R2b: `stand_up_relay_forced_topology`'s own convergence invariants --
//! N<->M and N<->W direct, M<->W relay in both directions, and (the whole
//! point of choosing M rather than N as the full replica) N genuinely does
//! not hold the blocks of a file M authors, so a peer fetching from N gets
//! nothing and a fetch through the relay to M is the only way to satisfy it.
//!
//! Deeper scenario tests (hydration-under-revocation, restart-while-relayed)
//! build on this helper directly; this file exists so a helper regression
//! shows up here first, not as a confusing failure three layers into one of
//! those.

mod support;

use support::fake_coordination::FakeCoordination;
use support::topology::stand_up_relay_forced_topology;
use support::wait_until_with_context;

const GROUP: &str = "relay-forced-smoke-group";

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn relay_forced_topology_converges_to_the_intended_routes() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();

    let (n, m, w, handles) = stand_up_relay_forced_topology(&fake, GROUP).await;

    // stand_up_relay_forced_topology's own wait_until already asserts this
    // on the way out; re-asserting explicitly here is what makes a helper
    // regression surface as THIS test's own failure message, not just an
    // opaque timeout inside a helper three call frames away.
    assert!(support::topology::fully_connected(&n.state, &m.device_id), "n<->m must be direct");
    assert!(support::topology::fully_connected(&n.state, &w.device_id), "n<->w must be direct");
    assert!(
        support::topology::routed_via_relay(&m.state, &w.device_id),
        "m->w must be routed via relay"
    );
    assert!(
        support::topology::routed_via_relay(&w.state, &m.device_id),
        "w->m must be routed via relay"
    );

    // The reason this topology exists at all: M (not N) is the full
    // replica, so a file M authors must be absent from N's own block
    // store -- N has nothing of its own to serve, and forwarding through
    // the relay is the only path a fetch can take.
    let payload = vec![0xCDu8; 128 * 1024];
    std::fs::write(m.root.path().join("relay-forced-smoke.bin"), &payload).unwrap();
    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .list_files(GROUP)
                .map(|files| {
                    files.iter().any(|f| {
                        f.path == "relay-forced-smoke.bin" && !f.deleted && !f.blocks.is_empty()
                    })
                })
                .unwrap_or(false)
        },
        std::time::Duration::from_secs(60),
        || {
            "w never saw a fully-populated (non-empty blocks) DAG record for \
             relay-forced-smoke.bin"
                .to_string()
        },
    )
    .await;

    let record = w
        .state
        .replica_coordinator
        .file_index_repository()
        .list_files(GROUP)
        .unwrap()
        .into_iter()
        .find(|f| f.path == "relay-forced-smoke.bin")
        .expect("record must exist after the wait above");
    let hashes: Vec<String> = record.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
    assert!(!hashes.is_empty(), "a non-empty payload must produce at least one block");
    let present_on_n = n.state.block_store.present_blocks(&hashes).unwrap();
    assert!(
        present_on_n.iter().all(|p| !p),
        "N must hold none of M's blocks -- otherwise a hydrate fetch could be satisfied \
         directly from N instead of genuinely going through the relay to M, which is exactly \
         the fault this topology exists to avoid: present_blocks={present_on_n:?}"
    );

    handles.shutdown();
}
