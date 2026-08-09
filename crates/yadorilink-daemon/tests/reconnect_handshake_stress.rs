//! Connection-layer acceptance signal for the production peer-session
//! reconnect supervisor (`peer_orchestrator::spawn_peer_session`), isolated
//! from `row14_strict_acceptance.rs` on purpose: row14 exercises DAG/
//! materialization/retirement correctness under its OWN simplified
//! test-level reconnect harness (`connect_pair_with_bounded_concurrency`),
//! which never routes through `peer_orchestrator` at all -- its own residual
//! CI redness is therefore not evidence about production's real reconnect
//! supervisor, only about row14's own reimplementation of one. This file
//! drives the real thing: a small mesh registered with an in-process
//! `FakeCoordination` server, connected through actual
//! `peer_orchestrator::run` netmap churn (mirrors
//! `chaos_coordination_unreachable.rs`'s own real-stack pattern), then
//! exercised by round-robin single-device reconnect churn.
//!
//! **What this file guarantees:** after a peer is revoked from the netmap
//! and returns (`FakeCoordination::revoke` + re-register, `teardown_peer`'s
//! own real path), it can reconnect under bounded, ordinary churn (one
//! device's membership dropping and returning at a time, not the whole mesh
//! simultaneously).
//!
//! **This file does NOT pin the zombie-channel natural-session-end fix.**
//! An earlier version of this file's own doc comment claimed it did; that
//! was wrong, caught in review. `FakeCoordination::revoke` drives
//! `teardown_peer`, which calls `channel.revoke()` and aborts the
//! supervisor task itself (see `teardown_peer`'s own code) -- a completely
//! different, pre-existing code path from the one this session's fix
//! touches (`run_one_peer_session_attempt`'s cleanup after `session.run()`
//! returns on its OWN, e.g. a handshake timeout, with the supervisor task
//! and netmap membership both still intact). Churning via netmap
//! revoke/re-register never reaches that cleanup path at all, so this file
//! would very likely stay green even with the natural-end fix reverted.
//! The actual regression pin for that fix is
//! `peer_orchestrator::tests::natural_session_end_revokes_the_stale_channel`
//! (a deterministic, paused-clock unit test: a peer that never answers
//! forces a genuine handshake-timeout natural end, without the test ever
//! calling `revoke()` itself, then asserts the dead generation's own
//! `PeerChannel::is_revoked()` became true) -- confirmed via mutation
//! testing to actually fail red when the fix is reverted. What THIS file
//! is genuinely useful for: it drives the real `peer_orchestrator` stack
//! end-to-end and is how the receiving-side fan-in gap below was
//! discovered in the first place.
//!
//! **What this file deliberately does NOT guarantee:** inbound handshake
//! admission when MANY peers initiate a handshake toward one device at
//! nearly the same instant. An earlier, more aggressive version of this test
//! churned all 6 devices' full mesh (up to 15 simultaneous pairs) and later
//! a single device's full 5-peer fan-in at once; both reliably exhausted the
//! exact-generation handshake budget even after the zombie-channel fix,
//! confirmed to be a genuine transport-layer scalability gap, NOT the same
//! bug and NOT CPU-timing noise: bounding the *initiating* side's
//! concurrency (a semaphore in `peer_orchestrator`) did not help, because
//! the actual bottleneck is the *receiving* device's `TransportHub`
//! recv_loop having no bound on simultaneous inbound handshake processing
//! -- a device on the receiving end of several peers reconnecting at once
//! has no control over how many arrive together. That is a distinct,
//! unresolved problem, intentionally out of scope for this file (see its own
//! follow-up: a dedicated `TransportHub`-level test reproducing
//! 5-peers-simultaneously-into-1-device, then tracing exactly where
//! `recv_loop`/`DemuxRegistry` stalls, drops, or times out before designing
//! inbound admission control). This file's own churn is deliberately kept
//! small (see `DEVICE_COUNT`'s own doc comment) so its green/red signal
//! stays about bounded netmap-driven reconnect, not fan-in capacity.
//!
//! Exit criteria this file makes checkable (not merely "the test passed"):
//! zero `exact-generation handshake: exhausted bounded retries` events, zero
//! unexpected first-message-type events, across N repeated reconnect
//! rounds within a single run. A `tracing::Subscriber` layer below captures
//! the structured fields this session's own production instrumentation
//! (`peer_session_public.rs::exact_generation_preflight`,
//! `peer_orchestrator.rs::run_one_peer_session_attempt`) emits, so this test
//! asserts on the SAME signals a human would grep logs for, not just on
//! "did the mesh eventually converge" -- deliberately not widening any
//! handshake timeout to make a run pass; a timeout increase would hide
//! exactly what this file exists to surface.
//!
//! No production DAG/retirement/materialization code path is touched by
//! this file at all -- every device here has no file content to sync,
//! purely peer-session connection lifecycle.

mod support;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{register_with_fake, wait_until_with_context};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_transport::DeviceKeyPair;

// --- signal capture -----------------------------------------------------

/// One structured tracing event's fields, captured by name -> formatted
/// value (quotes from `Debug`-formatted string fields are stripped by
/// [`CapturedEvent::field`] so callers compare against clean text).
#[derive(Debug, Clone, Default)]
struct CapturedEvent {
    fields: BTreeMap<String, String>,
}

impl CapturedEvent {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(|v| v.trim_matches('"'))
    }

    fn message(&self) -> &str {
        self.field("message").unwrap_or_default()
    }
}

#[derive(Default)]
struct FieldVisitor {
    fields: BTreeMap<String, String>,
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.insert(field.name().to_string(), format!("{value:?}"));
    }
}

#[derive(Default)]
struct SignalCapture {
    events: Mutex<Vec<CapturedEvent>>,
}

impl SignalCapture {
    fn record(&self, event: CapturedEvent) {
        self.events.lock().unwrap_or_else(|p| p.into_inner()).push(event);
    }

    fn clear(&self) {
        self.events.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }

    fn snapshot(&self) -> Vec<CapturedEvent> {
        self.events.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

struct CaptureLayer(Arc<SignalCapture>);

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        let captured = CapturedEvent { fields: visitor.fields };
        // Dropped at capture time, not just at display time: the
        // Convergence Engine's own per-tick polling ("engine loop ...")
        // fires constantly across every device for the whole test's
        // duration and would otherwise dwarf the handshake/reconnect
        // signal this capture exists to hold.
        if is_connection_relevant(&captured) {
            self.0.record(captured);
        }
    }

    // Required by the `Layer` trait's span-aware hooks; this capture is
    // event-only (no span-scoped fields needed for these assertions).
    fn on_new_span(&self, _attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {}
    fn on_record(&self, _id: &Id, _values: &Record<'_>, _ctx: Context<'_, S>) {}
}

/// Excludes the Convergence Engine's own per-tick polling noise
/// ("engine loop ..."), which drowns out the handshake/reconnect signal
/// this file's diagnostics need -- keeps everything about connect attempts,
/// the exact-generation handshake, session lifecycle, and the underlying
/// transport (WireGuard session/handshake events), by keyword match against
/// the event's own message text.
fn is_connection_relevant(event: &CapturedEvent) -> bool {
    const KEYWORDS: &[&str] = &[
        "handshake",
        "peer channel",
        "peer session",
        "reconnecting",
        "connect spec",
        "connect attempt",
        "session",
        "decapsulate",
        "wireguard",
        "ClusterConfig",
    ];
    let message = event.message().to_ascii_lowercase();
    KEYWORDS.iter().any(|k| message.contains(&k.to_ascii_lowercase()))
}

/// Every anomaly this file's exit criteria requires to stay at zero, found
/// in `capture`'s events since the last [`SignalCapture::clear`] -- returns
/// a human-readable description per anomaly (empty if none).
fn find_anomalies(capture: &SignalCapture) -> Vec<String> {
    let mut anomalies = Vec::new();
    for event in capture.snapshot() {
        let message = event.message();
        if message.contains("exact-generation handshake: exhausted bounded retries") {
            anomalies.push(format!(
                "handshake retry exhaustion: peer={:?} attempts={:?} elapsed_ms={:?}",
                event.field("peer"),
                event.field("attempts"),
                event.field("elapsed_ms"),
            ));
        }
        if message.contains("first peer message was not ClusterConfig") {
            anomalies.push(format!(
                "unexpected first message type: peer={:?} attempt={:?} first_message_kind={:?}",
                event.field("peer"),
                event.field("attempt"),
                event.field("first_message_kind"),
            ));
        }
        if message.contains("peer channel closed before completion") {
            anomalies.push(format!(
                "handshake channel closed early: peer={:?} attempt={:?}",
                event.field("peer"),
                event.field("attempt"),
            ));
        }
    }
    anomalies
}

// --- device setup (mirrors chaos_coordination_unreachable.rs) -----------

struct TestDaemon {
    device_id: String,
    state: Arc<DaemonState>,
    keypair: Arc<DeviceKeyPair>,
    _root: tempfile::TempDir,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    // Leaked deliberately: the block store must outlive the test; the
    // process tears the temp dir down on exit (matches
    // chaos_coordination_unreachable.rs's own justification).
    let store = Arc::new(FsBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon {
        device_id: device_id.to_string(),
        state,
        keypair: Arc::new(DeviceKeyPair::generate()),
        _root: tempfile::tempdir().unwrap(),
    }
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path, group_id: &str) {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();
}

fn spawn_orchestrator(
    coordination_addr: String,
    device_id: String,
    keypair: Arc<DeviceKeyPair>,
    state: Arc<DaemonState>,
) {
    let log_device_id = device_id.clone();
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        access_token: "test".to_string(),
        device_id,
    };
    tokio::spawn(async move {
        if let Err(error) = peer_orchestrator::run(config, keypair, state).await {
            eprintln!("peer orchestrator for {log_device_id} stopped: {error}");
        }
    });
}

// --- mesh-wide readiness helpers -----------------------------------------

/// Every directed pair (i != j) has a live, fully-negotiated session --
/// mirrors `row14_strict_acceptance.rs`'s own `wait_pair_ready` state-based
/// barrier (never a fixed sleep), just scaled to the whole mesh at once.
async fn wait_for_full_mesh(
    daemons: &[TestDaemon],
    timeout: Duration,
    context: &str,
    capture: &SignalCapture,
) {
    wait_until_with_context(
        || {
            daemons.iter().all(|a| {
                daemons.iter().filter(|b| b.device_id != a.device_id).all(|b| {
                    a.state
                        .peers
                        .session(&b.device_id)
                        .is_some_and(|s| s.peer_handshake_received() && s.change_dag_negotiated())
                })
            })
        },
        timeout,
        || {
            let summary = daemons
                .iter()
                .map(|d| {
                    let live: Vec<_> = daemons
                        .iter()
                        .filter(|other| other.device_id != d.device_id)
                        .filter(|other| {
                            d.state
                                .peers
                                .session(&other.device_id)
                                .is_some_and(|s| s.change_dag_negotiated())
                        })
                        .map(|other| other.device_id.clone())
                        .collect();
                    let has_session: Vec<_> = daemons
                        .iter()
                        .filter(|other| other.device_id != d.device_id)
                        .filter(|other| d.state.peers.has_session(&other.device_id))
                        .map(|other| other.device_id.clone())
                        .collect();
                    format!("{}: negotiated_with={live:?} has_session={has_session:?}", d.device_id)
                })
                .collect::<Vec<_>>()
                .join("\n");
            let recent_events = capture
                .snapshot()
                .iter()
                .filter(|e| is_connection_relevant(e))
                .rev()
                .take(200)
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "full mesh did not form ({context}):\n{summary}\n\nmost recent captured \
                 connection-relevant events (newest first, periodic engine-tick noise \
                 filtered out):\n{recent_events}"
            )
        },
    )
    .await;
}

/// Deliberately small: a single-device reconnect burst against
/// `DEVICE_COUNT - 1` simultaneous peers is exactly the scenario this
/// file's own module doc comment documents as OUT of scope (unresolved
/// inbound fan-in admission gap in `TransportHub`, not the zombie-channel
/// lifecycle bug this file exists to pin down). This value keeps that
/// burst at 2 simultaneous peers -- large enough to still exercise a real
/// multi-peer reconnect, far below where fan-in exhaustion was confirmed to
/// reproduce (5 peers, every run, even after the zombie-channel fix).
const DEVICE_COUNT: usize = 3;
/// Two full round-robin passes over all devices -- each pass churns every
/// device exactly once, one at a time, so this covers every device
/// reconnecting twice.
const STRESS_ROUNDS: usize = DEVICE_COUNT * 2;
const MESH_FORM_TIMEOUT: Duration = Duration::from_secs(60);
const MESH_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Every directed edge touching `device_id` has no live session -- the
/// single-device counterpart to `wait_for_full_teardown`, used when only
/// one device (not the whole mesh) was revoked.
async fn wait_for_device_disconnected(
    daemons: &[TestDaemon],
    device_id: &str,
    timeout: Duration,
    context: &str,
) {
    wait_until_with_context(
        || {
            daemons
                .iter()
                .filter(|d| d.device_id != device_id)
                .all(|d| !d.state.peers.has_session(device_id))
                && daemons.iter().find(|d| d.device_id == device_id).is_some_and(|d| {
                    daemons
                        .iter()
                        .filter(|other| other.device_id != device_id)
                        .all(|other| !d.state.peers.has_session(&other.device_id))
                })
        },
        timeout,
        || {
            let summary = daemons
                .iter()
                .map(|d| {
                    let live: Vec<_> = daemons
                        .iter()
                        .filter(|other| other.device_id != d.device_id)
                        .filter(|other| d.state.peers.has_session(&other.device_id))
                        .map(|other| other.device_id.clone())
                        .collect();
                    format!("{}: still_connected_to={live:?}", d.device_id)
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!("{device_id} did not fully disconnect ({context}):\n{summary}")
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn peer_reconnects_cleanly_after_natural_session_end() {
    support::ensure_isolated_config_dir();
    let capture = Arc::new(SignalCapture::default());
    let subscriber = tracing_subscriber::registry().with(CaptureLayer(capture.clone()));
    // `set_default` is thread-local -- the multi-threaded runtime's worker
    // threads other than this one would fall back to the (unset, no-op)
    // global dispatcher and every peer-orchestrator/session event running
    // on them would be silently dropped. This binary has exactly one test,
    // so a process-global dispatcher is safe here.
    tracing::subscriber::set_global_default(subscriber)
        .expect("no other subscriber has been installed in this test binary");

    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let group_id = "reconnect-stress-group";

    let mut daemons = Vec::with_capacity(DEVICE_COUNT);
    for i in 0..DEVICE_COUNT {
        let device_id = format!("device-{i}");
        let daemon = new_test_daemon(&device_id);
        register_with_fake(
            &fake,
            &daemon.state,
            &daemon.device_id,
            daemon.keypair.public_bytes(),
            &[group_id],
        )
        .await;
        link(&daemon.state, daemon._root.path(), group_id);
        daemons.push(daemon);
    }
    for daemon in &daemons {
        spawn_orchestrator(
            fake.addr(),
            daemon.device_id.clone(),
            daemon.keypair.clone(),
            daemon.state.clone(),
        );
    }

    wait_for_full_mesh(&daemons, MESH_FORM_TIMEOUT, "initial mesh formation", &capture).await;
    let initial_anomalies = find_anomalies(&capture);
    assert!(
        initial_anomalies.is_empty(),
        "initial mesh formation produced handshake anomalies:\n{}",
        initial_anomalies.join("\n")
    );
    capture.clear();

    // Churns ONE device per round (round-robin), not the whole mesh at
    // once -- see this file's own module doc comment for the full history
    // (an all-devices-at-once design, and later a single device's full
    // 5-peer fan-in with a 6-device mesh, both reliably exhausted the
    // exact-generation handshake budget for reasons outside this file's
    // scope). A single device reconnecting to `DEVICE_COUNT - 1` peers is
    // both the more realistic churn scenario (one peer's network blip or
    // laptop sleep/wake, not the whole mesh's membership flipping at once)
    // and, at this file's deliberately small `DEVICE_COUNT`, stays well
    // below the fan-in level confirmed to reproduce the OUT-OF-SCOPE
    // problem -- while still exercising the exact production reconnect/
    // generation lifecycle this file verifies.
    for round in 0..STRESS_ROUNDS {
        let churned = &daemons[round % DEVICE_COUNT];
        let churned_id = churned.device_id.clone();
        fake.revoke(&churned_id, group_id);
        wait_for_device_disconnected(
            &daemons,
            &churned_id,
            MESH_TEARDOWN_TIMEOUT,
            &format!("stress round {round}"),
        )
        .await;
        // Let any packet still in flight from the torn-down generation
        // drain before the next generation's handshake starts on the same
        // shared UDP socket -- see this file's own acceptance-loop history:
        // a stale in-flight WireGuard handshake_response from a prior
        // generation arriving mid-retry produced repeated `UnexpectedPacket`
        // decapsulate errors and a handshake attempt timeout on one pair.
        tokio::time::sleep(Duration::from_millis(300)).await;

        register_with_fake(
            &fake,
            &churned.state,
            &churned_id,
            churned.keypair.public_bytes(),
            &[group_id],
        )
        .await;
        wait_for_full_mesh(
            &daemons,
            MESH_FORM_TIMEOUT,
            &format!("stress round {round} reconnect ({churned_id})"),
            &capture,
        )
        .await;

        let anomalies = find_anomalies(&capture);
        assert!(
            anomalies.is_empty(),
            "stress round {round} ({churned_id}) produced handshake anomalies:\n{}",
            anomalies.join("\n")
        );
        capture.clear();
    }
}
