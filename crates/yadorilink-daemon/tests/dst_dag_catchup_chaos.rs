//! Repeated long-offline -> reconnect -> heal DST against the change-history
//! DAG's heads-announce catch-up.
//!
//! The scenario shape: a "laptop" that keeps going offline for long stretches
//! while an "always-on" device keeps writing — a hot path rewritten over and
//! over, plus fresh paths each cycle — and the laptop making its own offline
//! edits meanwhile. Each cycle is a full partition / heal: the two devices write
//! independently while cut off, then reconnect and drain the backlog. The cycles
//! repeat so that each heal starts from a longer shared history than the last.
//!
//! **What this file does and does not establish.** It is a sequential
//! partition/heal convergence test, not a test of *partial* catch-up. An earlier
//! version of this file claimed the latter and asserted that the laptop's
//! materialized file count never goes backwards between reconnects. That
//! assertion could not fail, and the claim it rested on was not true:
//!
//!   - The count is monotone *by construction*. This scenario generates no
//!     deletes and no renames, so files are only ever added to the laptop's
//!     tree. No behaviour of the system under test could drive the count down.
//!   - The lag it watched for does not occur at these timings. Measured on every
//!     default seed and every cycle, the laptop is *fully* caught up at each
//!     reconnect measurement point (9 -> 16 -> 23 -> 30 files, equal to the
//!     always-on device at every point), and stays fully caught up when the
//!     reconnect window is cut to 500ms.
//!
//! Tuning the window does not rescue that assertion: at 150ms the laptop
//! genuinely does lag (6 of 9, then 10 of 16, then 13 of 23), but the count
//! still only rises, so the assertion still cannot fire. It was therefore
//! removed rather than propped up. What is left is smaller and true.
//!
//! Shrinking the window that far is not a free knob, and the reason is worth
//! recording: at 150ms the *terminal* convergence then fails on some seeds, with
//! the laptop holding a live index row for a path whose bytes never landed —
//! the change propagated and materialization never finished, and ~90s of
//! connected time with a 50ms re-announce cadence does not repair it. That is a
//! real gap, it is not this file's to fix, and it is why the reconnect window
//! here is set where the backlog measurably drains: this file is meant to hold
//! the DAG's convergence honest, not to gate on that gap. The failure message
//! reports the live-row/no-bytes split so a future run says which layer stalled.
//!
//! Why the surviving assertions are what they are:
//!
//!   - *Terminal convergence on bytes* — both devices' trees must end
//!     byte-identical. Gated on content, not version vectors: a record the DAG
//!     materializes carries an empty `VersionVector`
//!     (`file_record_from_version` builds one with `VersionVector::new()`,
//!     since DAG causality lives in the change ancestry), so vector equality is
//!     unsatisfiable for a propagated path.
//!   - *No loss* — every value either device durably wrote must still be
//!     discoverable at the end, live or as a conflict copy. The hot path is
//!     rewritten every cycle, so only its final write need be live; the
//!     per-cycle unique paths must all survive intact.
//!
//! **This file is the named successor to `dst_intermittent_catchup_chaos.rs`,
//! deleted with the legacy mtime index-convergence engine.** That file published
//! every mutation through `PeerSyncSession::send_index_update`, which went with
//! the engine, so it could not compile — it was not a scenario that merely
//! needed retuning. Deleting a scenario is only honest if every property it
//! carried is accounted for, so here is the whole list, not the headline:
//!
//! Reproduced here, assertion for assertion:
//!
//!   - Repeated partition / heal cycles with both devices writing while cut off
//!     (`CYCLES`, the always-on and laptop writes below), a hot path rewritten
//!     every cycle (`HOT_PATH`), a startup canary (`CANARY_PATH`), terminal
//!     convergence on bytes, and no-loss. These are the shape it existed for.
//!
//! Carried by a named sibling instead, because this file's workload is
//! deliberately writes-only:
//!
//!   - **Deletes / tombstone propagation across a heal** —
//!     `dst_network_fault_chaos.rs`, which is DAG-driven, opens a timed full
//!     partition window, and runs `deliver_local_delete` under the full oracle
//!     battery.
//!   - **Renames and moves across a heal** — `dst_directory_chaos.rs`
//!     (`fs_ops::rename` under the same battery), and
//!     `dst_directory_move_edit_race.rs` for move-vs-edit ordering.
//!   - **The `GlobalOracle` battery** (Convergence, NoLoss, Corruption,
//!     ConflictCopyAccounting, and both Structural oracles) **and the
//!     `run_self_healing` sweep at quiescence** — the deleted file's declared
//!     oracle set was a strict *subset* of what `dst_network_fault_chaos`,
//!     `dst_two_device_chaos`, `dst_three_device_mesh_chaos`, and
//!     `dst_directory_chaos` each declare in `dst_support/impact_map.toml`.
//!   - **Pause / resume as a sync suppressant** — it drove `set_paused`, but
//!     only as its own harness send-gate; it asserted nothing about pause.
//!     The product property lives in `peer_session.rs`:
//!     `paused_link_does_not_apply_an_incoming_change` (both
//!     `handle_heads_announce` and `handle_change_batch` gate on
//!     `is_paused_for_group`) and
//!     `delete_vs_edit_conflict_tombstone_as_loser_leaves_no_ghost_file`, which
//!     uses pause as the partition and asserts the heal.
//!
//! Legacy-by-construction, dead with the engine:
//!
//!   - **Its `MAX_VV_COUNTER_JUMP_PER_MESSAGE` assertion** — that an honest
//!     >10,000 counter advance still fully heals despite the anti-forgery
//!     > clamp. This one is genuinely unsatisfiable now, and the mechanism is
//!     > gone rather than merely unused: `sanitize_against` has exactly one call
//!     > site (`apply_locked_record`), which has exactly one caller
//!     > (`rematerialize_one_record`), whose incoming record is a snapshot of
//!     > *this* device's own committed rows. The bound no longer sits on a peer
//!     > trust boundary at all, and a propagated record carries an empty vector
//!     > anyway. Its honest-growth-is-a-no-op property keeps unit coverage in
//!     > `version_vector.rs`. Note this assertion was flag-gated (first seed
//!     > only, and off entirely under a reduced ops budget) — it was that file's
//!     > soak dimension, not its core.
//!
//! Genuinely not covered, by this file or that one:
//!
//!   - **A large catch-up batch behind one heal.** The deleted file was widely
//!     described — including in its own comments — as hunting the recv-loop
//!     head-of-line stall with its 10,001-write probe. It could not have: that
//!     probe rewrote *one* path, and the heal then sent the whole index as
//!     `chunks(256)` — roughly two messages against a 64-permit
//!     `MAX_IN_FLIGHT_MESSAGES_PER_PEER` budget, with `BlockResponse` handled
//!     inline holding no permit. So this is a pre-existing gap that the
//!     deletion does not widen, not coverage lost. The DAG analogue would be a
//!     large missing-ancestry batch, and this file does not build one either:
//!     six writes per cycle drain well inside the reconnect window. The
//!     permanent-deadlock guard is structural in `run()` (the unbounded
//!     `pending` queue), and the stall's reproducer of record is the daemon
//!     end-to-end burst coverage, not a DST scenario.
//!
//! Propagation is the production DAG path: each device's
//! `LocalChangeProcessor` carries a signed `ChangeEmitter`, so an accepted
//! local mutation appends a signed change in the same transaction as its index
//! write, and the committing device announces its new heads. The peer's `run()`
//! loop diffs those heads, requests only the ancestry it lacks, and
//! materializes the same state. A partition here is full packet loss in both
//! directions on the simulated network.
//!
//! Two independent mechanisms can carry a head announcement across a partition,
//! and this scenario deliberately asserts the end-to-end outcome rather than
//! either one specifically: the transport's own retransmission of an announce
//! sent while partitioned, and the session's periodic frontier audit, which
//! re-sends an idempotent `HeadsAnnounce` every `maintenance_reconcile_interval`.
//! Measured, not assumed: pushing the periodic interval out past the end of the
//! run still converges (the transport alone suffices at this scenario's
//! timings), while removing the explicit `announce_local_commit` *and* the
//! periodic together leaves the laptop permanently missing every cycle's
//! writes. So the assertions below have teeth against catch-up breaking, but
//! they are not a test of the periodic audit in isolation — do not read a pass
//! here as evidence that the periodic re-drive works.

#![cfg(madsim)]

mod dst_dag_migrate_b2;
mod dst_support;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use dst_support::clock::HarnessClock;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_local_capture::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_peer_session::peer_session::PeerSyncSession;

const GROUP_ID: &str = "dst-dag-catchup-group";
const CANARY_PATH: &str = "startup-canary.bin";
const HOT_PATH: &str = "hot-counter.bin";
/// Long enough to be a genuine "the laptop was away for a while" window rather
/// than a blip the transport would have papered over with a retry.
const OFFLINE_WINDOW: Duration = Duration::from_secs(3);
/// Enough for a cycle's backlog to drain before the next partition. Measured:
/// the laptop is fully caught up at this window on every default seed, and stays
/// fully caught up all the way down to 500ms. Terminal convergence gets its own,
/// ample budget below.
const RECONNECT_WINDOW: Duration = Duration::from_secs(4);
/// Ample: the run's whole point is that the *final* reconnect heals fully.
/// Comfortably above the ~30s hydration timeout a lost block fetch can cost.
const FINAL_CONVERGENCE_BUDGET: Duration = Duration::from_secs(90);
const CYCLES: usize = 4;
/// Per-cycle writes on the always-on side. Enough that a cycle's catch-up is a
/// real batch (several changes plus their blocks), not a single record that
/// lands in one round trip.
const WRITES_PER_CYCLE: usize = 6;
const DEFAULT_VARIATIONS: u64 = 8;
const BASELINE_TIMEOUT_MARKER: &str = "BASELINE_TIMEOUT: ";
const TIME_LIMIT_MARKER: &str = "TIME_LIMIT: ";
const RESOURCE_EXHAUSTION_MARKER: &str = "RESOURCE_EXHAUSTION: ";

struct Device {
    device_id: String,
    root: PathBuf,
    state: Arc<ReplicaCoordinator>,
    processor: Arc<LocalChangeProcessor>,
    /// The current generation's live session, if any -- swapped, not
    /// set-once: `connect`'s reconnect supervisor replaces this every time
    /// a natural session end (not a test-driven partition) triggers a
    /// fresh generation, mirroring `peer_orchestrator::spawn_peer_session`'s
    /// production reconnect contract now that a `QuicPeerChannel` can end
    /// cleanly on its own (the QUIC connection idling out against a
    /// genuinely-partitioned peer) rather than only via an explicit revoke.
    session: StdMutex<Option<Arc<PeerSyncSession>>>,
}

fn setup_device(
    device_id: &str,
    root: PathBuf,
    state: Arc<ReplicaCoordinator>,
    store: Arc<FsBlockStore>,
) -> Arc<Device> {
    let processor = Arc::new(
        LocalChangeProcessor::new(
            state.clone(),
            store,
            device_id.to_string(),
            Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(dst_dag_migrate_b2::emitter_for(device_id)),
    );
    Arc::new(Device {
        device_id: device_id.to_string(),
        root,
        state,
        processor,
        session: StdMutex::new(None),
    })
}

/// Writes `content` to `path` on `device`, indexes it, and announces the
/// resulting heads. Bypasses the watcher/debounce boundary deliberately: this
/// scenario is about what catch-up does with a committed change, not about
/// local event coalescing (`dst_two_device_chaos.rs` covers that boundary).
async fn commit_local(
    device: &Arc<Device>,
    path: &str,
    content: &[u8],
    clock: &HarnessClock,
) -> Result<(), String> {
    let full = device.root.join(path);
    dst_support::fs_ops::write(clock, &full, content)?;
    let outcome = device
        .processor
        .process_event(
            GROUP_ID,
            &device.root,
            &FsChangeEvent { path: full, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .map_err(|e| e.to_string())?;
    if let LocalChangeOutcome::FileChanged(_) = &outcome {
        let current =
            device.session.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        if let Some(session) = current {
            // The emitter appended the signed change during `process_event`;
            // announce the heads. Announcing while partitioned is intentional:
            // production does not know it is partitioned either, and getting the
            // announcement across is the transport's and the periodic audit's
            // job (see this file's doc comment).
            let _ = session.announce_local_commit(GROUP_ID).await;
        }
    }
    Ok(())
}

/// Full packet loss in both directions == the laptop is off the network.
fn set_partitioned(partitioned: bool) {
    madsim::net::NetSim::current()
        .update_config(|cfg| cfg.packet_loss_rate = if partitioned { 1.0 } else { 0.0 });
}

/// The device's synced tree, as bytes on disk.
///
/// Skips the root-identity marker: every device mints its own token, so it is
/// the one file under a sync root that legitimately differs between fully
/// converged devices. It never syncs, but this walks the real filesystem rather
/// than the index, so it has to skip the marker itself or the byte-for-byte
/// terminal comparison below could never be satisfied.
fn snapshot(root: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(root) else { return out };
    for entry in entries.flatten() {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME {
                continue;
            }
            if let Ok(bytes) = std::fs::read(entry.path()) {
                out.insert(name, bytes);
            }
        }
    }
    out
}

/// One connect-then-run cycle for both sides of the laptop/always-on pair.
/// Returns each side's `PeerSyncSession::run` `JoinHandle` so [`connect`]'s
/// reconnect supervisor can wait for either to end and start a fresh
/// generation, rather than firing-and-forgetting them (the previous,
/// single-generation-only shape).
async fn connect_once(
    laptop: &Arc<Device>,
    store_l: Arc<FsBlockStore>,
    always_on: &Arc<Device>,
    store_a: Arc<FsBlockStore>,
) -> (
    tokio::task::JoinHandle<Result<(), yadorilink_peer_session::PeerSessionError>>,
    tokio::task::JoinHandle<Result<(), yadorilink_peer_session::PeerSessionError>>,
) {
    let (channel_l, channel_a) = quic_channel_pair(
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    )
    .await;

    // Pin both devices' verifying keys -- computed ahead of session
    // construction since `ChangeAuthenticator` is now a construction-only
    // `PeerSyncSessionDeps` field, not a post-hoc setter (`wire_dag_session`
    // below no longer installs it).
    let ids = [laptop.device_id.as_str(), always_on.device_id.as_str()];
    let authenticator = dst_dag_migrate_b2::PinnedAuthenticator::new(ids);

    let mut roots_l = HashMap::new();
    roots_l.insert(GROUP_ID.to_string(), laptop.root.clone());
    let session_l = PeerSyncSession::new_with_dependencies(
        channel_l,
        laptop.device_id.clone(),
        always_on.device_id.clone(),
        laptop.state.clone(),
        store_l,
        vec![GROUP_ID.to_string()],
        roots_l,
        None,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps {
            root_commit_authority_provider: std::sync::Arc::new(
                dst_support::link::TestRootCommitAuthorityProvider,
            ),
            change_authenticator: authenticator.clone(),
            ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
        },
    );
    let mut roots_a = HashMap::new();
    roots_a.insert(GROUP_ID.to_string(), always_on.root.clone());
    let session_a = PeerSyncSession::new_with_dependencies(
        channel_a,
        always_on.device_id.clone(),
        laptop.device_id.clone(),
        always_on.state.clone(),
        store_a,
        vec![GROUP_ID.to_string()],
        roots_a,
        None,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps {
            root_commit_authority_provider: std::sync::Arc::new(
                dst_support::link::TestRootCommitAuthorityProvider,
            ),
            change_authenticator: authenticator,
            ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
        },
    );

    *laptop.session.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some(session_l.clone());
    *always_on.session.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some(session_a.clone());
    let group_ids = [GROUP_ID];
    dst_dag_migrate_b2::wire_dag_session(&session_l, laptop.state.clone(), &ids, &group_ids);
    dst_dag_migrate_b2::wire_dag_session(&session_a, always_on.state.clone(), &ids, &group_ids);
    (tokio::spawn(session_l.run()), tokio::spawn(session_a.run()))
}

/// One authenticated QUIC connection between two loopback endpoints, as a
/// channel on each side -- the real transport, so a simulated run exercises
/// what ships rather than a substitute for it. Mirrors
/// `dst_three_device_mesh_chaos.rs`'s identical helper: a fresh signing
/// keypair per call is correct here too, since the pre-QUIC code this
/// replaced (`gen_keypair`) also generated a fresh transport keypair for
/// every reconnect generation rather than reusing one across the scenario.
async fn quic_channel_pair(
    socket_l: tokio::net::UdpSocket,
    socket_a: tokio::net::UdpSocket,
) -> (
    Arc<yadorilink_transport::QuicPeerChannel>,
    Arc<yadorilink_transport::QuicPeerChannel>,
) {
    use yadorilink_transport::{
        ConnectRole, DeviceSigningKeyPair, QuicPeerChannel, QuicPeerEndpoint, TransportHub,
    };
    let addr_a = socket_a.local_addr().unwrap();
    let key_l = DeviceSigningKeyPair::generate();
    let key_a = DeviceSigningKeyPair::generate();
    let public_l = key_l.public_bytes();
    let public_a = key_a.public_bytes();
    let endpoint_l = QuicPeerEndpoint::new(TransportHub::from_socket(socket_l), key_l).unwrap();
    let endpoint_a = QuicPeerEndpoint::new(TransportHub::from_socket(socket_a), key_a).unwrap();
    endpoint_l.authorize(public_a);
    endpoint_a.authorize(public_l);
    let accepting = {
        let endpoint_a = endpoint_a.clone();
        tokio::spawn(async move { endpoint_a.accept(public_l).await })
    };
    let dialed = endpoint_l.connect(addr_a, public_a).await.unwrap();
    let accepted = accepting.await.unwrap().unwrap();
    (
        QuicPeerChannel::new(dialed, ConnectRole::Dial),
        QuicPeerChannel::new(accepted, ConnectRole::Accept),
    )
}

/// Exponential backoff between reconnect attempts -- matches
/// `peer_orchestrator::spawn_peer_session`'s own production schedule
/// (`supervise::BackoffConfig::RECONNECT`: 1s doubling, capped at 45s)
/// rather than a fixed short delay. A fixed short delay is actively
/// dangerous under real CI-runner load: if a handshake is failing because
/// the runner is too contended to complete it in time (not because the
/// peer is genuinely gone), retrying every ~200ms just adds MORE
/// concurrent connect/handshake attempts on top of the contention that
/// caused the failure -- guaranteeing it never recovers. Confirmed for the
/// identical shape of supervisor in `row14_strict_acceptance.rs`'s own CI
/// run: 26 consecutive handshake failures over 321s with a fixed-delay
/// retry.
const RECONNECT_BACKOFF: yadorilink_daemon::supervise::BackoffConfig =
    yadorilink_daemon::supervise::BackoffConfig::RECONNECT;

/// Establishes the laptop/always-on pair and keeps them connected for the
/// rest of the scenario: a background supervisor watches both sides'
/// `PeerSyncSession::run` handles and starts a fresh generation (new
/// sockets, new `PeerChannel`s, new sessions, swapped into
/// `Device::session`) whenever either ends on its own. Before this existed,
/// a natural session end (e.g. the QUIC connection idling out against a
/// genuinely partitioned peer) permanently silenced that side of the pair
/// for the rest of the scenario -- indistinguishable, from this harness's point of
/// view, from the test's own intentional `set_partitioned` packet-loss
/// gate, except that a real partition heals (packet loss returns to 0) while
/// a torn-down-and-never-reconnected channel does not. This mirrors
/// `peer_orchestrator::spawn_peer_session`'s production reconnect contract
/// (see that function's own doc comment for the identical reasoning).
async fn connect(
    laptop: &Arc<Device>,
    store_l: Arc<FsBlockStore>,
    always_on: &Arc<Device>,
    store_a: Arc<FsBlockStore>,
) {
    let (mut h_l, mut h_a) =
        connect_once(laptop, store_l.clone(), always_on, store_a.clone()).await;

    let laptop = laptop.clone();
    let always_on = always_on.clone();
    tokio::spawn(async move {
        let mut attempt: u32 = 0;
        let mut generation_started = tokio::time::Instant::now();
        loop {
            // Cancel-safe: `select!` on `&mut JoinHandle` only consumes
            // whichever side actually resolved first; the other side's
            // handle is still valid to await (or select on again) later.
            // Both sides reconnect together regardless of which one ended
            // -- simpler than independently reconnecting one side while
            // exchanging its fresh candidate address with the other, and
            // just as correct for this harness's purposes (a lingering
            // live handle is dropped, which tears its own channel down via
            // the same `PeerChannel` Drop path a revoke would).
            tokio::select! {
                _ = &mut h_l => {}
                _ = &mut h_a => {}
            }
            // A generation that stayed up for a while was a genuine
            // success (this scenario's own partition/heal cycles are the
            // expected, healthy source of many reconnects over one run) --
            // reset the backoff instead of letting it ratchet toward its
            // 45s cap and stay there for the rest of the run. Only a
            // generation that dies almost immediately (handshake never
            // completing -- CI contention, or a peer that is not coming
            // back) escalates.
            if generation_started.elapsed() > Duration::from_secs(3) {
                attempt = 0;
            }
            tokio::time::sleep(RECONNECT_BACKOFF.next(attempt)).await;
            let (new_h_l, new_h_a) =
                connect_once(&laptop, store_l.clone(), &always_on, store_a.clone()).await;
            h_l = new_h_l;
            h_a = new_h_a;
            attempt = attempt.saturating_add(1);
            generation_started = tokio::time::Instant::now();
        }
    });
}

fn content_for(seed: u64, cycle: usize, seq: usize, tag: &str) -> Vec<u8> {
    format!("seed {seed} cycle {cycle} seq {seq} {tag}").into_bytes()
}

async fn run_scenario(seed: u64) -> Result<(), String> {
    let clock = HarnessClock::from_seed(seed);
    clock.install_as_session_clock();

    let dir_l = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_l = dir_l.path().canonicalize().map_err(|e| e.to_string())?;
    let sdir_l = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_l = Arc::new(FsBlockStore::new(sdir_l.path()).map_err(|e| e.to_string())?);
    let state_l = Arc::new(ReplicaCoordinator::open_in_memory().map_err(|e| e.to_string())?);
    dst_support::link::link_and_start(&state_l, &root_l, GROUP_ID)?;

    let dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_a = dir_a.path().canonicalize().map_err(|e| e.to_string())?;
    let sdir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_a = Arc::new(FsBlockStore::new(sdir_a.path()).map_err(|e| e.to_string())?);
    let state_a = Arc::new(ReplicaCoordinator::open_in_memory().map_err(|e| e.to_string())?);
    dst_support::link::link_and_start(&state_a, &root_a, GROUP_ID)?;

    let laptop = setup_device("device-laptop", root_l.clone(), state_l, store_l.clone());
    let always_on = setup_device("device-always-on", root_a.clone(), state_a, store_a.clone());
    set_partitioned(false);
    connect(&laptop, store_l, &always_on, store_a).await;

    // Startup gate: prove the session is actually up (handshake + a first
    // heads-announce round trip) before the cycles begin. Not part of what this
    // scenario tests -- a failure here is a host-load-dependent startup stall,
    // classified as a skip. (The old WireGuard-handshake-livelock attribution
    // was disproven -- issue #26: the one deterministic case was a harness
    // missing its convergence-driver wiring, which this file has.)
    commit_local(&always_on, CANARY_PATH, b"canary", &clock).await?;
    let canary_ok = dst_support::settle::settle_until(Duration::from_secs(20), || {
        std::fs::read(root_l.join(CANARY_PATH)).map(|c| c == b"canary").unwrap_or(false)
    })
    .await;
    if !canary_ok.converged {
        return Err(format!(
            "{BASELINE_TIMEOUT_MARKER}seed {seed}: the laptop never adopted the startup canary"
        ));
    }

    // Everything either device durably wrote, by path -> the bytes that must be
    // discoverable at the end. The hot path is overwritten every cycle, so its
    // entry is replaced (each rewrite cleanly supersedes the last by ancestry:
    // the always-on device is the only writer of it, and it is never concurrent
    // with itself); the per-cycle unique paths accumulate.
    let mut expected: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    expected.insert(CANARY_PATH.to_string(), b"canary".to_vec());

    for cycle in 0..CYCLES {
        set_partitioned(true);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The always-on device keeps working while the laptop is away: the hot
        // path rewritten every cycle, plus fresh paths only this cycle carries.
        for seq in 0..WRITES_PER_CYCLE {
            let path = format!("cycle-{cycle}-{seq}.bin");
            let bytes = content_for(seed, cycle, seq, "always-on");
            commit_local(&always_on, &path, &bytes, &clock).await?;
            expected.insert(path, bytes);
        }
        let hot = content_for(seed, cycle, 0, "hot");
        commit_local(&always_on, HOT_PATH, &hot, &clock).await?;
        expected.insert(HOT_PATH.to_string(), hot);

        // The laptop edits offline too, so each reconnect is a genuine
        // two-way catch-up rather than a one-way fetch.
        let laptop_path = format!("laptop-{cycle}.bin");
        let laptop_bytes = content_for(seed, cycle, 0, "laptop-offline");
        commit_local(&laptop, &laptop_path, &laptop_bytes, &clock).await?;
        expected.insert(laptop_path, laptop_bytes);

        tokio::time::sleep(OFFLINE_WINDOW).await;

        // Reconnect and let this cycle's backlog drain before the next
        // partition. At this window the drain measurably completes every time
        // (see the module doc comment), so each cycle hands the next one a
        // caught-up laptop and a longer shared history.
        set_partitioned(false);
        tokio::time::sleep(RECONNECT_WINDOW).await;
    }

    // Final heal: this one must fully converge.
    set_partitioned(false);
    let converged = dst_support::settle::settle_until(FINAL_CONVERGENCE_BUDGET, || {
        snapshot(&root_l) == snapshot(&root_a)
    })
    .await;

    let snap_l = snapshot(&root_l);
    let snap_a = snapshot(&root_a);
    if !converged.converged {
        let only_l: Vec<&String> = snap_l.keys().filter(|k| !snap_a.contains_key(*k)).collect();
        let only_a: Vec<&String> = snap_a.keys().filter(|k| !snap_l.contains_key(*k)).collect();
        let differing: Vec<&String> = snap_l
            .iter()
            .filter(|(k, v)| snap_a.get(*k).map(|o| o != *v).unwrap_or(false))
            .map(|(k, _)| k)
            .collect();
        // Whether the laptop's index carries a live row for a path whose bytes
        // never landed separates "the change never propagated" from "the change
        // propagated and materialization did not finish", which are different
        // bugs with different owners. Cheap to report and painful to re-derive.
        let live_rows_missing_bytes: Vec<String> = laptop
            .state
            .file_index_repository()
            .list_files(GROUP_ID)
            .map(|f| {
                f.iter()
                    .filter(|r| !r.deleted && only_a.iter().any(|p| **p == r.path))
                    .map(|r| r.path.clone())
                    .collect()
            })
            .unwrap_or_default();
        return Err(format!(
            "seed {seed}: the two devices never converged after the final heal (budget \
             {FINAL_CONVERGENCE_BUDGET:?}): only-on-laptop={only_l:?} only-on-always-on={only_a:?} \
             differing-content={differing:?} \
             laptop-has-live-index-row-but-no-bytes={live_rows_missing_bytes:?}"
        ));
    }

    // No loss: every durably-written value is still discoverable, live at its
    // own path or preserved as a conflict copy alongside it.
    let mut missing = Vec::new();
    for (path, bytes) in &expected {
        let found = snap_l.get(path).map(|b| b == bytes).unwrap_or(false)
            || snap_l.iter().any(|(name, b)| name.starts_with(stem_of(path)) && b == bytes);
        if !found {
            missing.push(path.clone());
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "seed {seed}: {} durably-written value(s) never reached the laptop and are not \
             preserved as a conflict copy: {missing:?}",
            missing.len()
        ));
    }
    Ok(())
}

/// The filename stem a conflict copy of `path` would share (`<stem> (conflicted
/// copy, ...).<ext>`), used to spot a value that survived under a renamed
/// sibling rather than at its own path.
fn stem_of(path: &str) -> &str {
    match path.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => path,
    }
}

fn run_in_madsim(seed: u64) -> Result<(), String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    // Comfortable margin over the cycles' own windows plus
    // FINAL_CONVERGENCE_BUDGET.
    rt.set_time_limit(Duration::from_secs(240));
    rt.block_on(run_scenario(seed))
}

/// Classifies only runtime-level failures (madsim's hard time limit and the
/// r2d2-maintenance-thread accumulation that eventually approaches `ulimit -u`)
/// as infrastructure. Scenario-level timeouts, including failure to adopt the
/// startup canary, are correctness failures and must remain visible.
fn run_seed(seed: u64) -> Result<(), String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_in_madsim(seed))) {
        Ok(result) => result,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "non-string panic payload".to_string());
            if msg.contains("time limit exceeded") {
                Err(format!("{TIME_LIMIT_MARKER}seed {seed}: {msg}"))
            } else if msg.contains("WouldBlock") || msg.contains("Resource temporarily unavailable")
            {
                Err(format!("{RESOURCE_EXHAUSTION_MARKER}seed {seed}: {msg}"))
            } else {
                Err(format!("seed {seed}: unexpected panic (not a known infra flake): {msg}"))
            }
        }
    }
}

fn is_infra_skip(error: &str) -> bool {
    error.starts_with(TIME_LIMIT_MARKER) || error.starts_with(RESOURCE_EXHAUSTION_MARKER)
}

#[test]
fn scenario_timeout_is_not_counted_as_infrastructure() {
    assert!(!is_infra_skip(&format!(
        "{BASELINE_TIMEOUT_MARKER}seed 7: startup canary was not adopted"
    )));
    assert!(is_infra_skip(&format!(
        "{TIME_LIMIT_MARKER}seed 7: simulated runtime time limit exceeded"
    )));
    assert!(is_infra_skip(&format!(
        "{RESOURCE_EXHAUSTION_MARKER}seed 7: Resource temporarily unavailable"
    )));
}

/// One network-touching `#[test]` fn, sequential over seeds -- madsim's
/// simulated network state is not safe across more than one such fn per binary
/// (the isolation finding `dst_peer_reconcile_race.rs` documents).
#[test]
fn dag_catchup_chaos_scenario() {
    let variations: u64 = std::env::var("DST_VARIATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_VARIATIONS);
    let base_seed: u64 =
        std::env::var("DST_BASE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0xDA6_CA70);

    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut skipped = 0u64;
    let mut failures = Vec::new();
    for i in 0..variations {
        let seed = base_seed.wrapping_add(i);
        match run_seed(seed) {
            Ok(()) => {}
            Err(e) if is_infra_skip(&e) => skipped += 1,
            Err(e) => failures.push(e),
        }
    }
    std::panic::set_hook(previous_hook);

    assert!(
        failures.is_empty(),
        "{}/{variations} DAG catch-up variations failed (skipped {skipped} on known \
         simulated-runtime infra conditions):\n{}\n(reproduce with DST_BASE_SEED=<seed> \
         DST_VARIATIONS=1 cargo test ... dag_catchup_chaos_scenario)",
        failures.len(),
        failures.join("\n---\n")
    );
    assert!(skipped < variations, "every seed was skipped -- nothing was actually exercised");
}
