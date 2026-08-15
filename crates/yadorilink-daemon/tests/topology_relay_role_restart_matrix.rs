//! M5-A Pass 8: three restart-during-relay scenarios the acceptance
//! matrix names but no existing file covers -- restarting each of the
//! three distinct roles a real relay session names
//! (`source`/`requester`, `relay`, `destination` -- `relay_session_e2e.
//! rs`'s own established terminology) while that session is actively in
//! use, on the real canonical N/M/W topology. `topology_restart_while_
//! relayed.rs` restarts the peer whose OWN traffic is relayed (a
//! destination/requester restarting itself); it does not restart the
//! RELAY node while it is actively forwarding for two OTHER peers, nor
//! does it restart one side of an in-flight relay session while the
//! OTHER side stays up mid-transfer.
//!
//! **Why every scenario's relay-carried traffic involves W specifically**:
//! only W's advertised endpoint is forced broken (this file's own
//! established technique, matching `topology_relay_failover.rs`), so W is
//! the ONLY node whose traffic is actually forced through relay -- N is
//! the sole relay-capable peer, and N cannot relay for itself, so an
//! earlier version of this file that authored content on M and merely
//! waited for N to converge was, in fact, exercising M<->N's own DIRECT
//! path the whole time (a Codex-review finding: proving nothing about
//! relay at all). Every scenario below therefore has W as either the
//! author (source/requester, relayed outbound to M) or the intended
//! receiver (destination, relayed inbound from M), and confirms the
//! `PeerReachability::Connected(RouteKind::Relay)` route signal is live
//! (the same production status signal `topology_relay_failover.rs`/
//! `topology_relay_fan_in_reconnect_chaos.rs` already established as
//! correct) right before the restart -- not just eventual content
//! convergence, which multi-hop DAG gossip through M could produce even
//! with zero relay traffic. An earlier version of this file tried to use
//! `DaemonState::relay_forwarder`'s session/byte-forwarded counters as
//! stronger evidence, but that forwarder measures a DIFFERENT mechanism
//! (the `RelayCarrier`/handoff-lease-style relay `relay_session_e2e.rs`/
//! `relay_chaos.rs` exercise), not ordinary `PeerChannel::connect_with_
//! relay` WireGuard-tunnel-via-relay sync traffic -- confirmed by that
//! attempt hanging waiting for forwarder activity that never came.
//!
//! In this canonical topology N is the sole relay-capable, full-replica
//! anchor -- the only possible `relay` role -- so:
//! - `relay_anchor_restart_mid_session`: N (the relay) restarts while
//!   W's route to M is confirmed still Relay, mid a large outbound
//!   transfer W authored.
//! - `requester_restart_mid_relay_session`: W (the side whose own
//!   outbound content must transit relay to reach M/N) restarts
//!   mid-transfer of a large payload.
//! - `destination_restart_mid_relay_session`: W (the side that must
//!   receive M's content via relay) restarts after seeing the DAG record
//!   but before hydrating it -- genuinely mid-fetch-decision, before its
//!   own relay-carried retrieval has completed.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{
    fully_connected, restart_node, spawn_orchestrator, stand_up_canonical_topology, TopologyNode,
};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_registry::PeerReachability;
use yadorilink_daemon::route::RouteKind;
use yadorilink_peer_session::peer_session::PeerSyncSession;

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

fn route_debug(state: &Arc<DaemonState>, peer_device_id: &str) -> &'static str {
    state.peers.reachability(peer_device_id).map(|r| r.route_str()).unwrap_or("no-session")
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

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("yadorilink_daemon=debug")),
        )
        .with_test_writer()
        .try_init();
}

fn lcg_payload(len: usize, seed: u64) -> Vec<u8> {
    let mut payload = vec![0u8; len];
    let mut state = seed;
    for byte in payload.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *byte = (state >> 56) as u8;
    }
    payload
}

/// Re-establishes N's full canonical role (full-replica + relay-capable)
/// after `restart_node` -- a fresh `DaemonState` starts with NEITHER,
/// and `register_with_fake`'s `fake.register_device` call overwrites the
/// coordination-plane record with `relay_capable: false`/no full-replica
/// groups too (a Codex-review finding on an earlier version of this
/// file: restarted N silently stopped being usable as a relay at all,
/// so every "post-restart relay" assertion was vacuously satisfied by
/// falling back to a DIFFERENT path, or simply never re-tested).
fn restore_n_canonical_role(fake: &FakeCoordination, n: &TopologyNode, group_id: &str) {
    fake.set_full_replica(&n.device_id, group_id, true);
    n.state.set_local_relay_capable(true);
    fake.set_relay_capable(&n.device_id, true);
}

/// Common setup for all three scenarios: canonical topology, W's direct
/// path forced broken so W's traffic (in either direction) must transit
/// relay through N.
async fn stand_up_with_w_relayed(
    group_id: &str,
) -> (TopologyNode, TopologyNode, TopologyNode, support::topology::TopologyHandles, FakeCoordination)
{
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();

    let (n, m, w, handles) = stand_up_canonical_topology(&fake, group_id).await;
    wire_relay_grant_source(&fake, &m.state, &m.device_id);
    wire_relay_grant_source(&fake, &w.state, &w.device_id);

    fake.update_endpoint(&w.device_id, "127.0.0.1:1".to_string());
    wait_until_with_context(
        || routed_via_relay(&m.state, &w.device_id) || routed_via_relay(&n.state, &w.device_id),
        Duration::from_secs(90),
        || {
            format!(
                "W's direct failure never produced a relay-routed session anywhere: \
                 m->w route={:?} n->w route={:?}",
                route_debug(&m.state, &w.device_id),
                route_debug(&n.state, &w.device_id),
            )
        },
    )
    .await;

    (n, m, w, handles, fake)
}

/// All three tests in this file are individually heavy (a full canonical
/// topology, a restart-and-reopen cycle, and an 8MB relay-carried
/// transfer each) -- `cargo test`'s default same-binary concurrency runs
/// them at the same time, and this specific combination was measured to
/// genuinely starve under real CPU/disk contention on ordinary dev
/// hardware (SQLite "database is locked" errors on `restart_node`'s own
/// reopen, and DAG-record waits timing out even at 150s, both confirmed
/// to disappear when run in isolation). Gating each test's ENTIRE body
/// behind this one mutex serializes them regardless of `cargo test`'s
/// own thread count, trading a bit of wall-clock time for reliability
/// that doesn't depend on the host machine's load.
static SERIALIZE_HEAVY_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_anchor_restart_mid_session() {
    let _serialize = SERIALIZE_HEAVY_TESTS.lock().await;
    init_tracing();
    let group_id = "topology-relay-anchor-restart-group";
    let (n, m, w, mut handles, fake) = stand_up_with_w_relayed(group_id).await;

    let n_session_with_m_before: Arc<PeerSyncSession> =
        n.state.peers.session(&m.device_id).expect("N must have a session with M before restart");
    let n_session_with_w_before: Arc<PeerSyncSession> =
        n.state.peers.session(&w.device_id).expect("N must have a session with W before restart");

    // W (the only relay-forced node) authors a payload large enough that
    // the relay forwarding it through N takes measurable time -- giving
    // a real window to land the restart mid-transfer rather than after
    // everything already quiesced (which would prove only "restart after
    // a relay route once existed", not "restart while forwarding"). The
    // route itself (not `RelayForwarder`'s session/byte counters, which
    // measure the SEPARATE `RelayCarrier`/handoff-lease-style relay
    // mechanism `relay_session_e2e.rs`/`relay_chaos.rs` exercise, not
    // ordinary `PeerChannel::connect_with_relay` WireGuard-tunnel-via-
    // relay sync traffic -- confirmed by this test's own earlier version
    // hanging on that assumption) is confirmed still Relay-routed right
    // before the restart, matching the same production status signal
    // used throughout this session's other relay tests.
    let payload = lcg_payload(6 * 1024 * 1024, 0xA1B2_C3D4_E5F6_0718);
    std::fs::write(w.root.path().join("relayed-by-w.bin"), &payload).unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        routed_via_relay(&m.state, &w.device_id) || routed_via_relay(&n.state, &w.device_id),
        "sanity check: W's route must still be Relay right before restarting the relay anchor \
         mid-transfer -- m->w route={:?} n->w route={:?}",
        route_debug(&m.state, &w.device_id),
        route_debug(&n.state, &w.device_id),
    );

    // Restart N -- the relay itself -- while W's large transfer is
    // plausibly still in flight over the just-confirmed relay route.
    handles.take_and_shutdown(&n.device_id).await;
    let n = restart_node(n).await;
    register_with_fake(&fake, &n.state, &n.device_id, n.keypair.public_bytes(), &[group_id]).await;
    restore_n_canonical_role(&fake, &n, group_id);
    let n_runtime = spawn_orchestrator(fake.addr(), &n);
    handles.insert(n.device_id.clone(), n_runtime);

    wait_until_with_context(
        || {
            n.state
                .peers
                .session(&m.device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &n_session_with_m_before))
                && n.state
                    .peers
                    .session(&w.device_id)
                    .is_some_and(|s| !Arc::ptr_eq(&s, &n_session_with_w_before))
        },
        Duration::from_secs(180),
        || "N never got FRESH session identities with M and W after restart".to_string(),
    )
    .await;
    wait_until_with_context(
        || fully_connected(&n.state, &m.device_id) && fully_connected(&n.state, &w.device_id),
        Duration::from_secs(90),
        || "N's fresh post-restart sessions with M and W never completed negotiation".to_string(),
    )
    .await;

    // W's transfer, however far it got before N's restart severed it,
    // must eventually converge to the EXACT payload once N (relay-
    // capable again) and W's own reconnect supervisor re-establish
    // relay -- proving the restarted relay anchor genuinely resumes
    // service rather than leaving the in-flight transfer permanently
    // stuck. M is On-Demand: waits for the DAG record, then explicitly
    // hydrates -- an earlier version of this test read M's placeholder
    // (same final size, but not yet real content) directly and failed
    // on a content mismatch that was a TEST bug, not a production one.
    // M5-A finding (see destination_restart_mid_relay_session's own
    // comment for the full writeup): `!f.deleted` alone is satisfied by
    // the DAG-admission bootstrap scaffold row, not proof the real
    // record has landed -- `has_real_current_row` is this codebase's own
    // documented distinguishing check.
    wait_until_with_context(
        || {
            m.state
                .replica_coordinator
                .file_index_repository()
                .has_real_current_row(group_id, "relayed-by-w.bin")
                .unwrap_or(false)
        },
        Duration::from_secs(150),
        || "M never saw relayed-by-w.bin's real DAG record after N's restart".to_string(),
    )
    .await;
    hydrate_with_retries(&m.state, group_id, "relayed-by-w.bin").await;
    let m_bytes =
        std::fs::read(m.root.path().join("relayed-by-w.bin")).expect("M must hold the file");
    assert_eq!(
        m_bytes, payload,
        "M's relay-hydrated copy of W's exact payload must be byte-exact after N's restart"
    );

    // A SECOND, fresh relayed write after the restart proves N's relay
    // role is durably restored, not just enough to flush the one
    // in-flight transfer. W's own endpoint is still forced-broken
    // (never restored in this test), so this write has no path but
    // relay.
    std::fs::write(w.root.path().join("after-anchor-restart.txt"), b"a fresh post-restart write")
        .unwrap();
    wait_until_with_context(
        || {
            m.state
                .replica_coordinator
                .file_index_repository()
                .has_real_current_row(group_id, "after-anchor-restart.txt")
                .unwrap_or(false)
        },
        Duration::from_secs(90),
        || {
            "M never saw W's fresh post-restart write's real DAG record over the restored relay \
             anchor"
                .to_string()
        },
    )
    .await;
    hydrate_with_retries(&m.state, group_id, "after-anchor-restart.txt").await;
    assert_eq!(
        std::fs::read(m.root.path().join("after-anchor-restart.txt")).ok().as_deref(),
        Some(b"a fresh post-restart write" as &[u8]),
        "M's hydrated copy of W's fresh post-restart write must be byte-exact"
    );

    handles.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requester_restart_mid_relay_session() {
    let _serialize = SERIALIZE_HEAVY_TESTS.lock().await;
    let group_id = "topology-requester-restart-mid-relay-group";
    let (n, m, mut w, mut handles, fake) = stand_up_with_w_relayed(group_id).await;

    let n_session_with_w_before: Arc<PeerSyncSession> =
        n.state.peers.session(&w.device_id).expect("N must have a session with W before restart");
    let m_session_with_w_before: Arc<PeerSyncSession> =
        m.state.peers.session(&w.device_id).expect("M must have a session with W before restart");

    // W is the requester here: its OWN outbound content is what must
    // transit relay (through N) to reach M and N. A large payload forces
    // the real reliable-delivery transfer to take measurable, multi-round
    // time, and W restarts shortly after starting the write, landing the
    // restart plausibly mid-relay-transfer.
    let payload = lcg_payload(8 * 1024 * 1024, 0x9E37_79B9_7F4A_7C15);
    std::fs::write(w.root.path().join("mid-relay-requester.bin"), &payload).unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;

    handles.take_and_shutdown(&w.device_id).await;
    w = restart_node(w).await;
    // W's direct endpoint is still the forced-broken one from before
    // restart; re-force it broken again after re-registration (the fix
    // `topology_restart_while_relayed.rs` established: re-registering
    // silently restores W's own freshly-bound real endpoint otherwise).
    register_with_fake(&fake, &w.state, &w.device_id, w.keypair.public_bytes(), &[group_id]).await;
    fake.update_endpoint(&w.device_id, "127.0.0.1:1".to_string());
    wire_relay_grant_source(&fake, &w.state, &w.device_id);
    let w_runtime = spawn_orchestrator(fake.addr(), &w);
    handles.insert(w.device_id.clone(), w_runtime);

    // Session-identity-first: BOTH N and M must replace their session
    // for W with a genuinely fresh one before trusting anything else.
    wait_until_with_context(
        || {
            n.state
                .peers
                .session(&w.device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &n_session_with_w_before))
                && m.state
                    .peers
                    .session(&w.device_id)
                    .is_some_and(|s| !Arc::ptr_eq(&s, &m_session_with_w_before))
        },
        Duration::from_secs(180),
        || "N and/or M never got a FRESH session identity for restarted requester W".to_string(),
    )
    .await;
    wait_until_with_context(
        || {
            fully_connected(&n.state, &w.device_id)
                && fully_connected(&m.state, &w.device_id)
                && (routed_via_relay(&m.state, &w.device_id)
                    || routed_via_relay(&n.state, &w.device_id))
        },
        Duration::from_secs(90),
        || {
            format!(
                "restarted requester W never re-established a negotiated, relay-routed \
                 session: m->w route={:?} n->w route={:?}",
                route_debug(&m.state, &w.device_id),
                route_debug(&n.state, &w.device_id),
            )
        },
    )
    .await;

    // Regardless of exactly when the restart landed relative to the
    // transfer, M must eventually converge on the EXACT payload -- no
    // stale partial/corrupted data accepted from the old requester
    // generation. M is On-Demand: waits for the DAG record, then
    // explicitly hydrates before comparing bytes.
    wait_until_with_context(
        || {
            m.state
                .replica_coordinator
                .file_index_repository()
                .has_real_current_row(group_id, "mid-relay-requester.bin")
                .unwrap_or(false)
        },
        Duration::from_secs(150),
        || {
            "M never saw mid-relay-requester.bin's real DAG record after the requester's restart"
                .to_string()
        },
    )
    .await;
    hydrate_with_retries(&m.state, group_id, "mid-relay-requester.bin").await;
    let m_bytes =
        std::fs::read(m.root.path().join("mid-relay-requester.bin")).expect("M must hold the file");
    assert_eq!(
        m_bytes, payload,
        "M's relay-hydrated copy of the mid-transfer payload must be byte-exact after the \
         requester's restart"
    );

    handles.shutdown();
}

// M5-A completion pass: this scenario's false-tombstone flake (the
// restarted W's re-synced record showing `deleted: true` for a file
// that was never actually deleted) is RESOLVED -- three distinct real
// bugs stacked together to produce it, each fixed in turn and validated
// with 60+ isolated runs at 0 recurrence after the final fix (previously
// ~20-30%):
//
// 1. `peer_session.rs::materialize()` had two call sites (the
//    eager-incomplete `!all_present` branch and the OnDemand-not-pinned
//    "no block fetch at all" branch) that committed a fresh index row
//    before either demoting to `MaterializationState::Placeholder` or
//    creating the on-disk placeholder, with no `MaterializationIntentGuard`
//    bracketing. Fixed by opening the guard before the row commit and
//    clearing it only after the placeholder write durably lands.
// 2. The startup reconciliation scan (`local_change.rs`) only checked
//    `has_materialization_intent` before tombstoning a locally-missing
//    path -- but a path can have a durably-committed, non-deleted index
//    row whose materialization JOB is still queued (`Pending`/`Backoff`),
//    with no intent ever opened for it yet. Fixed by also checking
//    `has_pending_materialization_job`.
// 3. The actual proximate cause of most of the residual: `get_file`/
//    `list_files` cannot distinguish a real content-bearing row from
//    `apply_incoming_wire_metadata`'s own `version_seq == 0` bootstrap
//    scaffold row (`file_index.rs::ensure_bootstrap_row_for_metadata`)
//    -- a deliberate, documented placeholder written for a newly-admitted
//    path BEFORE `materialize`/`materialize_dag_content_head` has run at
//    all. Both this test's own `!f.deleted`-only wait conditions AND
//    `hydration.rs::hydrate_inner`'s "already hydrated" fast path trusted
//    that ambiguous state -- the fast path in particular could report
//    success for a genuinely-empty scaffold, silently handing back zero
//    bytes. Fixed by using the codebase's own existing, documented
//    distinguishing check, `has_real_current_row`, in both places.
//
// See `hydration.rs::hydrate_inner`'s own comments at both fixed
// checkpoints for the production-side detail, and project memory
// `m5a-pass9-link-runtime-stop-fence-gap`'s Pass-11 addendum (a
// DIFFERENT, still-open bug this investigation also surfaced but did
// not need to touch to close this one) for what's still tracked
// separately.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destination_restart_mid_relay_session() {
    let _serialize = SERIALIZE_HEAVY_TESTS.lock().await;
    init_tracing();
    let group_id = "topology-destination-restart-mid-relay-group";
    let (n, m, mut w, mut handles, fake) = stand_up_with_w_relayed(group_id).await;

    let n_session_with_w_before: Arc<PeerSyncSession> =
        n.state.peers.session(&w.device_id).expect("N must have a session with W before restart");
    let m_session_with_w_before: Arc<PeerSyncSession> =
        m.state.peers.session(&w.device_id).expect("M must have a session with W before restart");

    // M authors a payload; W is the DESTINATION that must fetch it via
    // relay (through N) once it's OnDemand-fetched. Wait only for W to
    // see the DAG record -- deliberately BEFORE calling `hydrate` at
    // all -- so W restarts genuinely before its own relay-carried
    // retrieval has started, not mid-completed-transfer.
    let payload = lcg_payload(8 * 1024 * 1024, 0x243F_6A88_85A3_08D3);
    std::fs::write(m.root.path().join("mid-relay-destination.bin"), &payload).unwrap();
    // M5-A finding: `list_files`'s `!f.deleted` alone is satisfied by
    // `apply_incoming_wire_metadata`'s own `version_seq == 0` bootstrap
    // scaffold row -- a real, if usually brief, admitted-but-not-yet-
    // projected state, NOT proof the real record (real size/blocks
    // metadata, still legitimately un-hydrated for OnDemand -- that part
    // of this scenario's own intent is unaffected) has actually landed.
    // `has_real_current_row` is this codebase's own documented
    // distinguishing check for exactly this ambiguity.
    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .has_real_current_row(group_id, "mid-relay-destination.bin")
                .unwrap_or(false)
        },
        Duration::from_secs(60),
        || {
            "W (pre-restart) never saw mid-relay-destination.bin's real DAG record (only ever \
             the bootstrap scaffold, if anything)"
                .to_string()
        },
    )
    .await;

    handles.take_and_shutdown(&w.device_id).await;
    w = restart_node(w).await;
    register_with_fake(&fake, &w.state, &w.device_id, w.keypair.public_bytes(), &[group_id]).await;
    fake.update_endpoint(&w.device_id, "127.0.0.1:1".to_string());
    wire_relay_grant_source(&fake, &w.state, &w.device_id);
    let w_runtime = spawn_orchestrator(fake.addr(), &w);
    handles.insert(w.device_id.clone(), w_runtime);

    wait_until_with_context(
        || {
            n.state
                .peers
                .session(&w.device_id)
                .is_some_and(|s| !Arc::ptr_eq(&s, &n_session_with_w_before))
                && m.state
                    .peers
                    .session(&w.device_id)
                    .is_some_and(|s| !Arc::ptr_eq(&s, &m_session_with_w_before))
        },
        Duration::from_secs(180),
        || "N and/or M never got a FRESH session identity for restarted destination W".to_string(),
    )
    .await;
    wait_until_with_context(
        || {
            fully_connected(&n.state, &w.device_id)
                && fully_connected(&m.state, &w.device_id)
                && (routed_via_relay(&m.state, &w.device_id)
                    || routed_via_relay(&n.state, &w.device_id))
        },
        Duration::from_secs(90),
        || {
            format!(
                "restarted destination W never re-established a negotiated, relay-routed \
                 session: m->w route={:?} n->w route={:?}",
                route_debug(&m.state, &w.device_id),
                route_debug(&n.state, &w.device_id),
            )
        },
    )
    .await;

    // W, once its fresh post-restart generation re-establishes relay,
    // must eventually see the DAG record again and hydrate the EXACT
    // content -- proving the restarted destination doesn't get stuck
    // never resuming its own relay-carried fetch.
    // Same `has_real_current_row` distinction as the pre-restart wait
    // above: a fresh post-restart scaffold row (re-admitted metadata
    // whose real projection hasn't run yet) must not be mistaken for the
    // real record either, or the immediately-following `hydrate` below
    // can be handed a genuinely-empty scaffold and (correctly, for that
    // record) reconstruct zero bytes -- confirmed as the actual
    // mechanism behind this scenario's residual flake.
    wait_until_with_context(
        || {
            w.state
                .replica_coordinator
                .file_index_repository()
                .has_real_current_row(group_id, "mid-relay-destination.bin")
                .unwrap_or(false)
        },
        // Wider than the other similar post-restart DAG-record waits in
        // this file: this specific wait was observed flaking (timing out
        // at 90s) when this file's 3 tests run concurrently in the same
        // binary (each an 8-worker-thread topology, so real CPU
        // contention under the default `cargo test` concurrent-test
        // execution, not a correctness issue -- confirmed by every
        // isolated run of this scenario passing comfortably faster).
        Duration::from_secs(150),
        || {
            let query_result =
                w.state.replica_coordinator.file_index_repository().list_files(group_id).map(
                    |files| files.iter().map(|f| (f.path.clone(), f.deleted)).collect::<Vec<_>>(),
                );
            format!(
                "restarted W never saw the REAL DAG record (only the bootstrap scaffold, if \
                 anything) over its fresh relay-routed session -- list_files \
                 query_result={query_result:?}"
            )
        },
    )
    .await;
    hydrate_with_retries(&w.state, group_id, "mid-relay-destination.bin").await;
    let w_bytes = std::fs::read(w.root.path().join("mid-relay-destination.bin"))
        .expect("restarted W must eventually hold the file");
    assert_eq!(
        w_bytes, payload,
        "restarted W's relay-hydrated copy of the payload must be byte-exact"
    );

    handles.shutdown();
}
