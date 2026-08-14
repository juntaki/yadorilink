//! M5-A Pass 5 (restart truthfulness): a daemon restart on the canonical
//! N/M/W topology must never resurrect a stale `Protected` reading
//! without fresh evidence -- the SAME property M4's own
//! `restart_never_shows_a_stale_protected_status` unit test proves for a
//! single reopened `ReplicaCoordinator`, proven here through a REAL
//! multi-node restart: a genuinely different `DaemonState` process
//! instance, reopened against the same on-disk state, with real peers
//! still running and a real re-handshake required before any fresh
//! evidence can exist again.
//!
//! **Oracle discipline**: `fully_connected` (`peer_handshake_received`/
//! `change_dag_negotiated`) reads sticky `AtomicBool`s on
//! `PeerSyncSession` that, once set, never reset for that session
//! object's lifetime -- a valid "has this session EVER negotiated"
//! check, but NOT a valid "is the CURRENT session fresh" check, since a
//! stale session object sitting in the registry (never replaced) would
//! read identically to a genuinely fresh one. This file's own restart
//! scenario therefore proves session REPLACEMENT by `Arc` identity
//! (`!Arc::ptr_eq(old, new)`) FIRST, and only checks negotiation flags
//! on the confirmed-fresh session object.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{fully_connected, restart_node, stand_up_canonical_topology};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::durability_service::GroupDurabilityStatus;
use yadorilink_peer_session::peer_session::PeerSyncSession;

/// Installs a `tracing` subscriber writing to the test harness (visible
/// with `--nocapture`) at a verbosity that captures the full session-
/// generation lifecycle this file's own module doc comment describes:
/// supervisor generation start, `PeerChannel`/`PeerSyncSession`
/// creation, registry insert, actor exit reason, `PeerSyncSession::run`
/// exit, reconnect-loop backoff/next-attempt, WireGuard handshake
/// initiation/authentication. Test-local only (matches this crate's
/// established `relay_failover.rs`-style pattern) -- no new production-
/// visible tracing was added; every event below already exists in
/// `peer_orchestrator.rs`/`peer_channel.rs`/`peer_session.rs`'s
/// production code, this just makes it visible.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    "yadorilink_daemon=debug,yadorilink_transport=debug,yadorilink_peer_session=debug",
                )
            }),
        )
        .with_test_writer()
        .try_init();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn n_restart_never_shows_a_stale_protected_status() {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-restart-group";

    let (n, m, w, mut handles) = stand_up_canonical_topology(&fake, group_id).await;

    // Establish a genuine Protected-eligible baseline: real content
    // converges, then a real custody-confirmation sweep runs. This
    // topology is a lone-full-replica-anchor shape (established fact,
    // `topology_n_m_w.rs`), so the reachable status is AtRisk -- but the
    // property under test (stale evidence must not survive a restart)
    // applies identically regardless of which non-Unknown status was
    // reached, so this still exercises it directly: assert a REAL,
    // non-Unknown status is reached before restart, then prove restart
    // doesn't let it survive un-reconfirmed.
    let path = m.root.path().join("before-restart.txt");
    std::fs::write(&path, b"before restart").unwrap();
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join("before-restart.txt")).ok().as_deref()
                == Some(b"before restart" as &[u8])
        },
        Duration::from_secs(30),
        || "N never converged on M's pre-restart content".to_string(),
    )
    .await;
    n.state.refresh_custody_confirmation(group_id).await;
    let pre_restart_status = n.state.group_durability_status(group_id);
    assert_ne!(
        pre_restart_status,
        GroupDurabilityStatus::Unknown,
        "sanity check: a genuine non-Unknown status must be established before restart, so \
         the post-restart assertion below actually proves \"reset to Unknown\", not merely \
         \"happens to also read Unknown\""
    );

    // Capture the PRE-restart session identity on M and W's side --
    // this is the "old PeerSyncSession" the module doc comment's
    // lifecycle starts from.
    let m_session_before: Arc<PeerSyncSession> = m
        .state
        .peers
        .session(&n.device_id)
        .expect("M must have an established session with N before restart");
    let w_session_before: Arc<PeerSyncSession> = w
        .state
        .peers
        .session(&n.device_id)
        .expect("W must have an established session with N before restart");
    tracing::info!(
        m_session_before = ?Arc::as_ptr(&m_session_before),
        w_session_before = ?Arc::as_ptr(&w_session_before),
        "TEST: captured pre-restart session identities"
    );

    // Restart N: shut down ONLY N's own orchestrator runtime (M/W's own
    // orchestrators must keep running -- their reconnect supervisors are
    // what actually notice N coming back; a plain `drop(handles)` would
    // wrongly kill every node's orchestrator, not just N's --
    // `take_and_shutdown`'s own doc comment) and its link runtime
    // (`restart_node`'s own `LinkRuntimeController::stop` call), then
    // reopen a fresh `DaemonState` against the exact same on-disk index
    // DB and block store.
    handles.take_and_shutdown(&n.device_id).await;
    let n = restart_node(n).await;
    tracing::info!(
        "TEST: N restarted -- old orchestrator/link runtime torn down, fresh DaemonState opened"
    );

    // Immediately after restart, BEFORE any new peer handshake or
    // custody-confirmation sweep has run, durability must read Unknown
    // -- never the pre-restart status resurrected from stale in-memory
    // state, since there IS no in-memory state anymore; this is really
    // asserting that nothing about `DaemonState::new`'s own
    // reconstruction from disk fabricates fresh-looking evidence that
    // was never actually re-confirmed this process instance.
    assert_eq!(
        n.state.group_durability_status(group_id),
        GroupDurabilityStatus::Unknown,
        "a freshly restarted daemon must report Unknown until its OWN confirmation sweep \
         has run, never the pre-restart status"
    );

    // Re-register with the coordination plane (a real restart re-runs
    // the orchestrator's own startup registration) and re-spawn the
    // orchestrator so N can reconnect to M and W -- through the SAME
    // dedicated-child-runtime `spawn_orchestrator` the initial mesh
    // uses, registered back into `handles` (`TopologyHandles::insert`),
    // so this fresh generation's own per-peer supervisors are tracked
    // and torn down at the test's end exactly like the original three
    // nodes' -- a bare `tokio::spawn` here (an earlier version of this
    // test) would leak them the same way finding #2 of an M5-A Pass 5
    // Codex review found for the ORIGINAL design.
    register_with_fake(&fake, &n.state, &n.device_id, n.keypair.public_bytes(), &[group_id]).await;
    let n_runtime = support::topology::spawn_orchestrator(fake.addr(), &n);
    handles.insert(n.device_id.clone(), n_runtime);
    tracing::info!("TEST: N's fresh orchestrator spawned, re-registered with coordination plane");

    // Step 1 of the required lifecycle: the OLD session must be
    // REPLACED by a genuinely different `PeerSyncSession` object on
    // BOTH M and W -- not merely "still has a session" (a stale one
    // sitting in the registry would pass that trivially). Deliberately
    // does NOT require observing an intermediate `None`: replacement
    // may legitimately happen faster than this polling interval, and a
    // registry slot going briefly empty is an implementation detail,
    // not a required observable state.
    wait_until_with_context(
        || {
            let m_replaced = m
                .state
                .peers
                .session(&n.device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &m_session_before));
            let w_replaced = w
                .state
                .peers
                .session(&n.device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &w_session_before));
            m_replaced && w_replaced
        },
        Duration::from_secs(180),
        || {
            format!(
                "M/W never got a FRESH session identity for N after restart (still the same \
                 pre-restart Arc, or no session at all): m_session={:?} w_session={:?}",
                m.state.peers.session(&n.device_id).map(|s| Arc::as_ptr(&s)),
                w.state.peers.session(&n.device_id).map(|s| Arc::as_ptr(&s)),
            )
        },
    )
    .await;
    tracing::info!("TEST: M and W both replaced their session for N with a fresh Arc identity");

    // Step 2: only NOW check negotiation flags -- on the confirmed-
    // fresh session, this is a valid signal (a stale session's sticky
    // flags could never have told us anything at this point).
    wait_until_with_context(
        || fully_connected(&m.state, &n.device_id) && fully_connected(&w.state, &n.device_id),
        Duration::from_secs(60),
        || {
            format!(
                "fresh sessions never completed negotiation: m={:?} w={:?}",
                m.state
                    .peers
                    .session(&n.device_id)
                    .map(|s| (s.peer_handshake_received(), s.change_dag_negotiated())),
                w.state
                    .peers
                    .session(&n.device_id)
                    .map(|s| (s.peer_handshake_received(), s.change_dag_negotiated())),
            )
        },
    )
    .await;
    tracing::info!("TEST: fresh sessions negotiated -- proceeding to real traffic");

    // Step 3: real application traffic over the fresh session, exact
    // content verified -- not just "a session object exists." M is
    // On-Demand (this canonical topology's own established shape), so
    // the DAG job settling (visible in the trace as "job marked
    // Completed after direct projection verification") lands the file
    // as a placeholder first; explicit `hydration::hydrate` (the same
    // real entry point a real OS-provider callback drives, matching
    // `topology_n_m_w.rs`'s own established pattern) is required before
    // checking actual bytes -- an earlier version of this test wrongly
    // expected `std::fs::read` to see content immediately.
    let path = n.root.path().join("after-restart.txt");
    std::fs::write(&path, b"content authored after N's restart").unwrap();
    wait_until_with_context(
        || {
            m.state
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == "after-restart.txt" && !f.deleted))
                .unwrap_or(false)
        },
        // A negotiated session can still hit a brief liveness re-race mid-
        // restart-recovery (the same jitter the hydrate-retry loop right
        // below this already documents/tolerates) -- 30s cut it too close
        // and produced hard failures in ~2/5 local runs with the DAG
        // record simply not there YET, not permanently missing. Matches
        // the margin already granted to the negotiation wait above it.
        Duration::from_secs(90),
        || "M never saw after-restart.txt's DAG record over the fresh session".to_string(),
    )
    .await;
    // A single `hydrate` attempt can genuinely race a still-settling
    // fresh generation (a brief re-race/liveness cycle mid-restart-
    // recovery) and return `HydrationFailed` even though N does hold the
    // content and the session is fundamentally healthy -- the same
    // transient outcome a real UI/CLI consumer must retry through,
    // documented on `hydrate`'s own doc comment ("Reverts to Placeholder
    // and returns HydrationFailed if the deadline elapses"). Retried a
    // few times rather than requiring the very first attempt to land in
    // exactly the right window.
    let mut hydrate_attempts = 0;
    loop {
        match yadorilink_daemon::hydration::hydrate(&m.state, group_id, "after-restart.txt").await {
            Ok(()) => break,
            Err(error) if hydrate_attempts < 5 => {
                hydrate_attempts += 1;
                tracing::warn!(
                    %error,
                    hydrate_attempts,
                    "TEST: hydration attempt failed, retrying (transient generation churn)"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(error) => panic!(
                "hydration should eventually succeed once the fresh session's peer holds the \
                 content, after {hydrate_attempts} retries: {error}"
            ),
        }
    }
    wait_until_with_context(
        || {
            std::fs::read(m.root.path().join("after-restart.txt")).ok().as_deref()
                == Some(b"content authored after N's restart" as &[u8])
        },
        Duration::from_secs(10),
        || "M never converged on N's post-restart content over the fresh session".to_string(),
    )
    .await;

    // Once N has genuinely reconnected and run a fresh confirmation
    // sweep, it must reach the SAME real status the pre-restart baseline
    // reached (this topology's own structural fact hasn't changed) --
    // proving the post-restart Unknown was a truthful transient, not a
    // permanently-stuck state.
    n.state.refresh_custody_confirmation(group_id).await;
    assert_eq!(
        n.state.group_durability_status(group_id),
        pre_restart_status,
        "after reconnecting and re-sweeping post-restart, N must reach the same real status \
         the pre-restart baseline did -- the restart must be a truthful transient dip to \
         Unknown, not a permanent regression"
    );

    // Teardown: `handles` (Drop impl) shuts down every tracked runtime,
    // including N's post-restart generation now that it's registered
    // via `handles.insert` above -- proving a second restart would also
    // find something in `take_and_shutdown` for N, closing finding #2.
    handles.shutdown();
}

/// M5-A Pass 5 regression-matrix item B/C (restart of a NON-anchor node):
/// the canonical topology is a full mesh (N<->M, N<->W, M<->W all
/// connected, `stand_up_canonical_topology`'s own wait proves this), so
/// restarting M or W -- unlike N, which is the lone full-replica/relay
/// anchor and has its own dedicated durability-status test above -- must
/// be observed from BOTH of the other two nodes at once, not just one.
/// Proves the same session-identity-first lifecycle N's own restart test
/// proves (fresh `Arc<PeerSyncSession>` on every remaining peer before
/// trusting negotiation flags), plus real bidirectional content
/// convergence: the restarted node's own pre-restart authorship must
/// still be held by its peers, and its post-restart authorship must
/// reach them again over the fresh session. Does not repeat the
/// N-restart test's `group_durability_status` assertions -- that
/// machinery is evaluated from the full-replica anchor's perspective
/// (N), which does not restart in this scenario, so there is nothing new
/// to prove there; "stale evidence must not survive a restart" is
/// already covered once, structurally, by the N-restart test above.
async fn on_demand_node_restart_recovers_and_resyncs(restart_w: bool) {
    init_tracing();
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "topology-restart-group";

    let (n, mut m, mut w, mut handles) = stand_up_canonical_topology(&fake, group_id).await;
    let label = if restart_w { "W" } else { "M" };

    // The restarting node authors the baseline file; BOTH other nodes
    // must converge on it before restart (Eager N via a direct read; the
    // other On-Demand node via `hydration::hydrate`, exactly like the
    // N-restart test's own established pattern for an On-Demand reader).
    let before_name = format!("before-restart-{label}.txt");
    {
        let author_root = if restart_w { w.root.path() } else { m.root.path() };
        std::fs::write(author_root.join(&before_name), b"before restart").unwrap();
    }
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join(&before_name)).ok().as_deref()
                == Some(b"before restart" as &[u8])
        },
        Duration::from_secs(30),
        || format!("N never converged on {label}'s pre-restart content"),
    )
    .await;
    let bystander_hydrate_before = if restart_w { &m.state } else { &w.state };
    wait_until_with_context(
        || {
            bystander_hydrate_before
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == before_name && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(30),
        || format!("the bystander On-Demand peer never saw {label}'s pre-restart DAG record"),
    )
    .await;
    yadorilink_daemon::hydration::hydrate(bystander_hydrate_before, group_id, &before_name)
        .await
        .expect("bystander hydration of the pre-restart baseline should succeed");

    let restart_device_id = if restart_w { w.device_id.clone() } else { m.device_id.clone() };
    let n_session_before: Arc<PeerSyncSession> =
        n.state.peers.session(&restart_device_id).unwrap_or_else(|| {
            panic!("N must have an established session with {label} before restart")
        });
    let bystander_state_before = if restart_w { &m.state } else { &w.state };
    let bystander_session_before: Arc<PeerSyncSession> =
        bystander_state_before.peers.session(&restart_device_id).unwrap_or_else(|| {
            panic!(
                "the bystander peer must have an established session with {label} before restart"
            )
        });

    // Restart the target node exactly like the N-restart test does:
    // tear down ONLY its own orchestrator runtime, reopen it against the
    // same on-disk state, re-register, and re-spawn a fresh orchestrator
    // tracked back into `handles`.
    if restart_w {
        handles.take_and_shutdown(&w.device_id).await;
        w = restart_node(w).await;
        register_with_fake(&fake, &w.state, &w.device_id, w.keypair.public_bytes(), &[group_id])
            .await;
        let runtime = support::topology::spawn_orchestrator(fake.addr(), &w);
        handles.insert(w.device_id.clone(), runtime);
    } else {
        handles.take_and_shutdown(&m.device_id).await;
        m = restart_node(m).await;
        register_with_fake(&fake, &m.state, &m.device_id, m.keypair.public_bytes(), &[group_id])
            .await;
        let runtime = support::topology::spawn_orchestrator(fake.addr(), &m);
        handles.insert(m.device_id.clone(), runtime);
    }
    tracing::info!(label, "TEST: restarted node's orchestrator re-spawned and re-registered");

    let bystander_state_after = if restart_w { &m.state } else { &w.state };
    wait_until_with_context(
        || {
            let n_replaced = n
                .state
                .peers
                .session(&restart_device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &n_session_before));
            let bystander_replaced = bystander_state_after
                .peers
                .session(&restart_device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &bystander_session_before));
            n_replaced && bystander_replaced
        },
        Duration::from_secs(180),
        || format!("N and/or the bystander peer never got a FRESH session identity for {label}"),
    )
    .await;
    wait_until_with_context(
        || {
            fully_connected(&n.state, &restart_device_id)
                && fully_connected(bystander_state_after, &restart_device_id)
        },
        Duration::from_secs(60),
        || format!("fresh sessions with restarted {label} never completed negotiation"),
    )
    .await;
    tracing::info!(label, "TEST: fresh sessions with restarted node negotiated");

    // Real post-restart traffic authored BY the restarted node, over the
    // fresh session, must reach BOTH other nodes again.
    let after_name = format!("after-restart-{label}.txt");
    let content = format!("content authored after {label}'s restart");
    {
        let author_root = if restart_w { w.root.path() } else { m.root.path() };
        std::fs::write(author_root.join(&after_name), content.as_bytes()).unwrap();
    }
    wait_until_with_context(
        || {
            std::fs::read(n.root.path().join(&after_name)).ok().as_deref()
                == Some(content.as_bytes())
        },
        Duration::from_secs(90),
        || format!("N never converged on {label}'s post-restart content over the fresh session"),
    )
    .await;
    wait_until_with_context(
        || {
            bystander_state_after
                .replica_coordinator
                .file_index_repository()
                .list_files(group_id)
                .map(|files| files.iter().any(|f| f.path == after_name && !f.deleted))
                .unwrap_or(false)
        },
        Duration::from_secs(90),
        || format!("bystander peer never saw {label}'s post-restart DAG record"),
    )
    .await;
    yadorilink_daemon::hydration::hydrate(bystander_state_after, group_id, &after_name)
        .await
        .expect("bystander hydration of the post-restart content should succeed");

    handles.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn m_restart_recovers_and_resyncs_with_both_peers() {
    on_demand_node_restart_recovers_and_resyncs(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn w_restart_recovers_and_resyncs_with_both_peers() {
    on_demand_node_restart_recovers_and_resyncs(true).await;
}
