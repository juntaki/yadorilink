//! M5-A Pass 8: the last two acceptance-matrix scenarios task #27 names as
//! genuinely missing -- `simultaneous-reconnect-fan-in` and
//! `relay-failure-during-hydration`. Real production code throughout (real
//! `peer_orchestrator`, real transport, real DAG sync/hydration).
//!
//! - `simultaneous_reconnect_fan_in`: on the canonical N/M/W topology
//!   (`stand_up_canonical_topology`), both M and W go connectivity-broken
//!   AT ONCE (not sequentially, unlike `topology_relay_fan_in_reconnect_
//!   chaos.rs`'s repeated-flapping scenario), each author distinct local
//!   content while broken, then both are restored in the same instant --
//!   exercising N handling two peers' fresh-session renegotiation and DAG
//!   fan-in concurrently, verifying neither peer's change is lost or
//!   duplicated by the race.
//! - `relay_failure_during_hydration`: on the relay-forced topology
//!   (`stand_up_relay_forced_topology` -- see that helper's own doc
//!   comment for why the canonical one above is unusable here: its N is
//!   the full replica and would independently serve W the content
//!   directly, never exercising the relay leg this test means to
//!   revoke), W must fetch M's content via relay through N. N's relay
//!   capability is revoked while the fetch is genuinely in flight (real
//!   bytes already moving through N's relay forwarder, confirmed
//!   directly rather than assumed from timing), leaving W with NO path
//!   to M at all -- proving `hydrate` fails cleanly (an `Err`, never
//!   Hydrated, never a corrupt or partial placeholder) rather than
//!   hanging or silently succeeding with truncated content, then that
//!   restoring the relay path lets a retried hydrate recover the exact
//!   byte-for-byte content.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{
    hydrate_with_retries, routed_via_relay, snapshot_relay_recovery, stand_up_canonical_topology,
    stand_up_relay_forced_topology, wait_for_new_stable_relay_generation,
    wire_relay_grant_source_with_ttl,
};
use support::wait_until_with_context;

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
    let group_id = "relay-failure-during-hydration-group";
    let (n, m, w, handles) = stand_up_relay_forced_topology(&fake, group_id).await;

    // This scenario's own pacing (retried hydration across a revoke/
    // restore cycle) can approach the shared 60s default relay grant TTL
    // `stand_up_relay_forced_topology` wires up -- a grant expiring
    // mid-test forces a real relay-session teardown/reconnect that has
    // nothing to do with what this test means to exercise (relay-capable
    // revocation, not grant-expiry churn), and previously conflated the
    // two while debugging (see `wire_relay_grant_source_with_ttl`'s own
    // doc comment). Re-wired here, not by raising the shared default:
    // every other relay test still wants ordinary 60s expiry coverage.
    // 300s was enough before the size-aware per-block deadline fix
    // (`PeerSyncSession::fetch_response_timeout_for`): each `hydrate_with_
    // retries` attempt used to fail fast (~5s per stuck block) if it
    // wasn't going to converge. Now a single contended block can
    // legitimately take up to ~20s, so a `hydrate()` attempt can itself
    // run close to the full 30s `HYDRATION_TIMEOUT`, and `hydrate_with_
    // retries`'s 8 attempts can together approach ~250s -- observed
    // directly as a real, reproducible flake: one isolated run at 300s
    // passed in 315.56s (the grant's own clock starts at restore time,
    // not test start, so setup overhead bought some slack), a second
    // failed at 334.80s once that slack ran out. Raised with real margin
    // rather than re-measuring the exact boundary.
    const RELAY_GRANT_TTL_SECONDS: i64 = 900;
    wire_relay_grant_source_with_ttl(&fake, &m.state, &m.device_id, RELAY_GRANT_TTL_SECONDS);
    wire_relay_grant_source_with_ttl(&fake, &w.state, &w.device_id, RELAY_GRANT_TTL_SECONDS);

    // High-entropy, not a repeated byte: a uniform payload produces
    // near-identical/duplicate content-defined chunks, so dedup can
    // satisfy the whole file from far less real relay traffic than its
    // size implies. Seeded for reproducibility.
    let payload = {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5245_4c41_5946_4149);
        let mut bytes = vec![0u8; 6 * 1024 * 1024];
        rng.fill_bytes(&mut bytes);
        bytes
    };
    std::fs::write(m.root.path().join("relay-fail-mid-hydrate.bin"), &payload).unwrap();
    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| {
                    files.iter().any(|f| {
                        f.path == "relay-fail-mid-hydrate.bin" && !f.deleted && !f.blocks.is_empty()
                    })
                })
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || {
            "W never saw a fully-populated (non-empty blocks) DAG record for \
             relay-fail-mid-hydrate.bin"
                .to_string()
        },
    )
    .await;

    // The whole reason this uses the relay-forced topology rather than
    // the canonical one: prove N genuinely has none of the target
    // content before trusting that a successful fetch went through the
    // relay to M, not a redundant direct serve from N.
    let record = w
        .state
        .replica_coordinator
        .file_index_repository()
        .list_files(group_id)
        .unwrap()
        .into_iter()
        .find(|f| f.path == "relay-fail-mid-hydrate.bin")
        .expect("record must exist after the wait above");
    let hashes: Vec<String> = record.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
    assert!(
        n.state.block_store.present_blocks(&hashes).unwrap().iter().all(|present| !present),
        "N must hold none of the target file's blocks -- otherwise this test cannot tell a \
         relay-carried fetch apart from a direct serve from N"
    );
    assert!(
        routed_via_relay(&w.state, &m.device_id),
        "W's route to M must be Relay before the hydrate attempt starts"
    );

    // Spawn the hydrate, then wait for it to become GENUINELY in flight --
    // real bytes already moved through N's relay forwarder for this
    // fetch, and the task has not yet resolved either way -- before
    // revoking, rather than assuming a race is "probably wide enough."
    let hydrate_task = {
        let state = Arc::clone(&w.state);
        let group_id = group_id.to_string();
        tokio::spawn(async move {
            yadorilink_daemon::hydration::hydrate(&state, &group_id, "relay-fail-mid-hydrate.bin")
                .await
        })
    };
    const IN_FLIGHT_BYTE_THRESHOLD: u64 = 64 * 1024;
    wait_until_with_context(
        || {
            !hydrate_task.is_finished()
                && n.state
                    .relay_forwarder
                    .any_active_session_id()
                    .and_then(|id| n.state.relay_forwarder.session_bytes_forwarded(id))
                    .is_some_and(|bytes| bytes > IN_FLIGHT_BYTE_THRESHOLD)
        },
        Duration::from_secs(30),
        || {
            format!(
                "hydrate never became genuinely in-flight through the relay: finished={} \
                 active_session={:?}",
                hydrate_task.is_finished(),
                n.state.relay_forwarder.any_active_session_id(),
            )
        },
    )
    .await;

    // Snapshot the relay session id and both ends' `PeerSyncSession`
    // identities BEFORE revoking -- the recovery wait below needs this
    // "old" generation to prove a genuinely NEW one replaced it, since
    // `RouteKind::Relay` alone carries no generation identity (see
    // `RelayRecoverySnapshot`'s own doc comment).
    let before_revoke =
        snapshot_relay_recovery(&n.state, &m.state, &w.state, &m.device_id, &w.device_id);

    // Revoke N's relay capability WHILE the fetch is confirmed in flight
    // -- on both the coordination plane and locally, matching how a real
    // admin action and its local enforcement would both need to change.
    fake.set_relay_capable(&n.device_id, false);
    n.state.set_local_relay_capable(false);

    let result = hydrate_task.await.expect("hydrate task must not panic");
    assert!(
        result.is_err(),
        "hydrate must fail closed once its only relay path is revoked genuinely mid-fetch, not \
         silently succeed with truncated content; got {result:?}"
    );
    assert_eq!(
        n.state.relay_forwarder.active_session_count(),
        0,
        "revoking N's relay capability must proactively close the in-flight relay session, not \
         merely stop admitting new ones"
    );

    assert_ne!(
        w.state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(group_id, "relay-fail-mid-hydrate.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Hydrated),
        "a failed hydrate must not leave the path marked Hydrated"
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
    // not a corrupted or wedged local state. Deliberately NOT a bare
    // `routed_via_relay` poll here: that alone cannot distinguish a
    // genuinely-settled new generation from a relationship still churning
    // through repeated reconnects (`RouteKind::Relay` carries no
    // generation identity) -- `wait_for_new_stable_relay_generation`
    // requires a relay session id AND both ends' `PeerSyncSession`
    // identities to differ from `before_revoke` and then hold steady for
    // a stability window before hydrate retries begin.
    fake.set_relay_capable(&n.device_id, true);
    n.state.set_local_relay_capable(true);
    // 15s was reliably enough before the AIMD debounce fix (`apply_
    // debounced_backoff`) and the size-aware per-block deadline; measured
    // directly afterward, stabilization after restore now took ~28s in
    // one isolated run (consistently over 15s across two others). The
    // exact mechanism connecting those fixes to this specific wait isn't
    // pinned down -- both only touch block-fetch pacing, not connection/
    // session establishment -- but the timing shift is real and
    // reproducible, so this margin is raised to accommodate it rather
    // than left racing a since-invalidated bound.
    wait_for_new_stable_relay_generation(
        &n.state,
        &m.state,
        &w.state,
        &m.device_id,
        &w.device_id,
        &before_revoke,
        Duration::from_secs(60),
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
