//! M5-A Pass 8: the last two acceptance-matrix scenarios task #27 names as
//! genuinely missing -- `simultaneous-reconnect-fan-in` and
//! `relay-failure-during-hydration`. Real production code throughout (real
//! `peer_orchestrator`, real transport, real DAG sync/hydration), on the
//! canonical N/M/W topology (`stand_up_canonical_topology`): N is the
//! Eager, full-replica, relay-capable anchor; M and W are OnDemand.
//!
//! - `simultaneous_reconnect_fan_in`: both M and W go connectivity-broken
//!   AT ONCE (not sequentially, unlike `topology_relay_fan_in_reconnect_
//!   chaos.rs`'s repeated-flapping scenario), each author distinct local
//!   content while broken, then both are restored in the same instant --
//!   exercising N handling two peers' fresh-session renegotiation and DAG
//!   fan-in concurrently, verifying neither peer's change is lost or
//!   duplicated by the race.
//! - `relay_failure_during_hydration`: W (OnDemand, direct path forced
//!   broken) must fetch M's content via relay through N. N's relay
//!   capability is revoked while the fetch is genuinely in flight, leaving
//!   W with NO path to M at all -- proving `hydrate` fails cleanly
//!   (`Unknown fails informationally closed`: an `Err`, not a corrupt or
//!   partial placeholder) rather than hanging or silently succeeding with
//!   truncated content, then that restoring the relay path lets a retried
//!   hydrate recover the exact byte-for-byte content.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::stand_up_canonical_topology;
use support::wait_until_with_context;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_registry::PeerReachability;
use yadorilink_daemon::route::RouteKind;

struct FakeGrantSource {
    fake: FakeCoordination,
    source_device_id: String,
}

impl yadorilink_daemon::relay_carrier::RelayGrantSource for FakeGrantSource {
    fn request_relay_grant<'a>(
        &'a self,
        destination_device_id: &'a str,
        _relay_device_id: &'a str,
        _group_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Option<yadorilink_daemon::relay_grant::RelayGrant>>
                + Send
                + 'a,
        >,
    > {
        let grant = self.fake.issue_relay_grant(&self.source_device_id, destination_device_id, 60);
        Box::pin(async move { grant })
    }
}

fn wire_relay_grant_source(fake: &FakeCoordination, state: &Arc<DaemonState>, device_id: &str) {
    state.set_relay_grant_source(Arc::new(FakeGrantSource {
        fake: fake.clone(),
        source_device_id: device_id.to_string(),
    }));
}

fn routed_via_relay(state: &Arc<DaemonState>, peer_device_id: &str) -> bool {
    matches!(
        state.peers.reachability(peer_device_id),
        Some(PeerReachability::Connected(RouteKind::Relay))
    )
}

async fn hydrate_with_retries(state: &Arc<DaemonState>, group_id: &str, path: &str) {
    let mut attempts = 0;
    loop {
        match yadorilink_daemon::hydration::hydrate(state, group_id, path).await {
            Ok(()) => return,
            Err(error) if attempts < 8 => {
                attempts += 1;
                tracing::warn!(%error, attempts, path, "hydration attempt failed, retrying");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => panic!("hydration of {path} should eventually succeed: {error}"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn simultaneous_reconnect_fan_in() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();

    let (n, m, w, handles) = stand_up_canonical_topology(&fake, "sim-reconnect-fan-in-group").await;
    let group_id = "sim-reconnect-fan-in-group";

    // Break M and W's direct endpoints AT THE SAME TIME (not one after the
    // other) -- both lose their route to N (and to each other) in one
    // instant. Neither is relay-wired here: this scenario is about
    // simultaneous *reconnection*, not relay routing.
    let real_m_endpoint = m.state.shared_socket().unwrap().local_addr().to_string();
    let real_w_endpoint = w.state.shared_socket().unwrap().local_addr().to_string();
    fake.update_endpoint(&m.device_id, "127.0.0.1:1".to_string());
    fake.update_endpoint(&w.device_id, "127.0.0.1:1".to_string());
    // Not waiting for an explicit "disconnected" reachability state here,
    // matching `topology_relay_failover.rs`'s own established pattern:
    // production's reconnect supervisor may never settle into a clean
    // steady "disconnected" (it can move straight into repeated reconnect
    // attempts), so the only reliable thing to assert on is the eventual
    // POSITIVE outcome below, not an intermediate negative one. A short
    // fixed pause after breaking both endpoints is enough for the next
    // handshake attempt (which is what will actually fail, forcing
    // reconnection later) to be underway before content is authored.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Each authors distinct content while both are broken.
    std::fs::write(m.root.path().join("from-m.bin"), b"content authored by M while broken")
        .unwrap();
    std::fs::write(w.root.path().join("from-w.bin"), b"content authored by W while broken")
        .unwrap();
    // Give the local watchers time to pick these up and commit local DAG
    // records before either peer's connectivity is restored, so the fan-in
    // that follows is genuinely of two ALREADY-COMMITTED, independent
    // changes racing to reach N at once -- not a race with the local
    // capture pipeline itself.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Restore BOTH at once.
    fake.update_endpoint(&m.device_id, real_m_endpoint);
    fake.update_endpoint(&w.device_id, real_w_endpoint);

    wait_until_with_context(
        || {
            n.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| {
                    files.iter().any(|f| f.path == "from-m.bin" && !f.deleted)
                        && files.iter().any(|f| f.path == "from-w.bin" && !f.deleted)
                })
                .unwrap_or(false)
        },
        Duration::from_secs(90),
        || {
            let query_result =
                n.state.replica_coordinator.file_index_repository().list_files(group_id).map(
                    |files| files.iter().map(|f| (f.path.clone(), f.deleted)).collect::<Vec<_>>(),
                );
            format!(
                "N (full-replica anchor) never fanned in both simultaneous reconnects: \
                 query_result={query_result:?}"
            )
        },
    )
    .await;

    // N is Eager -- its own materialization must hold the exact bytes for
    // both, proving neither change was lost or corrupted by the
    // simultaneous-renegotiation race.
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join("from-m.bin")).ok().as_deref()
                == Some(b"content authored by M while broken".as_slice())
                && std::fs::read(n.root.path().join("from-w.bin")).ok().as_deref()
                    == Some(b"content authored by W while broken".as_slice())
        },
        Duration::from_secs(60),
        || "N never fully materialized both simultaneously-reconnected peers' content".to_string(),
    )
    .await;

    // And the two OnDemand peers must each eventually see BOTH records
    // (their own, plus the other's, gossiped via N) -- proving the fan-in
    // is genuinely group-wide, not just N-centric.
    wait_until_with_context(
        || {
            m.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "from-w.bin" && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || "M never saw W's simultaneously-authored change".to_string(),
    )
    .await;
    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "from-m.bin" && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || "W never saw M's simultaneously-authored change".to_string(),
    )
    .await;

    handles.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn relay_failure_during_hydration() {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();

    let group_id = "relay-failure-during-hydration-group";
    let (n, m, w, handles) = stand_up_canonical_topology(&fake, group_id).await;
    wire_relay_grant_source(&fake, &m.state, &m.device_id);
    wire_relay_grant_source(&fake, &w.state, &w.device_id);

    // Force W's direct path broken -- N (the sole relay-capable peer) is
    // W's only route to M.
    fake.update_endpoint(&w.device_id, "127.0.0.1:1".to_string());

    let payload = vec![0xABu8; 6 * 1024 * 1024];
    std::fs::write(m.root.path().join("relay-fail-mid-hydrate.bin"), &payload).unwrap();
    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| {
                    files.iter().any(|f| f.path == "relay-fail-mid-hydrate.bin" && !f.deleted)
                })
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || "W never saw the DAG record for relay-fail-mid-hydrate.bin".to_string(),
    )
    .await;
    wait_until_with_context(
        || routed_via_relay(&m.state, &w.device_id) || routed_via_relay(&n.state, &w.device_id),
        Duration::from_secs(60),
        || "W never established a relay-routed session before the hydrate attempt".to_string(),
    )
    .await;

    // Revoke N's relay capability WHILE the hydrate is genuinely in
    // flight: spawn the hydrate, then immediately break N's relay
    // capability on the coordination plane and locally, racing the fetch
    // itself rather than merely testing a pre-broken relay.
    let hydrate_task = {
        let state = Arc::clone(&w.state);
        let group_id = group_id.to_string();
        tokio::spawn(async move {
            yadorilink_daemon::hydration::hydrate(&state, &group_id, "relay-fail-mid-hydrate.bin")
                .await
        })
    };
    fake.set_relay_capable(&n.device_id, false);
    n.state.set_local_relay_capable(false);

    let result = hydrate_task.await.expect("hydrate task must not panic");
    assert!(
        result.is_err(),
        "hydrate must fail closed once its only relay path is revoked mid-fetch, not silently \
         succeed with truncated content"
    );

    // Fail-closed must mean genuinely absent/placeholder content, never a
    // corrupt partial file masquerading as complete.
    let post_failure_bytes = std::fs::read(w.root.path().join("relay-fail-mid-hydrate.bin"));
    if let Ok(bytes) = post_failure_bytes {
        assert_ne!(
            bytes, payload,
            "a failed hydrate must not have produced the full correct payload"
        );
        assert!(
            bytes.iter().all(|&b| b == 0),
            "a failed hydrate's on-disk remnant must be an untouched placeholder (all zero), not \
             partially-written real content"
        );
    }

    // Restore N's relay capability and confirm a retried hydrate fully
    // recovers -- proving the failure was a clean, recoverable rejection,
    // not a corrupted or wedged local state.
    fake.set_relay_capable(&n.device_id, true);
    n.state.set_local_relay_capable(true);
    wait_until_with_context(
        || routed_via_relay(&m.state, &w.device_id) || routed_via_relay(&n.state, &w.device_id),
        Duration::from_secs(60),
        || {
            "W never re-established a relay-routed session after relay capability was restored"
                .to_string()
        },
    )
    .await;
    hydrate_with_retries(&w.state, group_id, "relay-fail-mid-hydrate.bin").await;
    let recovered_bytes = std::fs::read(w.root.path().join("relay-fail-mid-hydrate.bin"))
        .expect("W must hold the file after a successful retried hydrate");
    assert_eq!(
        recovered_bytes, payload,
        "the retried hydrate's recovered content must be byte-exact"
    );

    handles.shutdown();
}
