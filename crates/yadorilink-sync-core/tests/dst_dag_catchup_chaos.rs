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
//!     clamp. This one is genuinely unsatisfiable now, and the mechanism is
//!     gone rather than merely unused: `sanitize_against` has exactly one call
//!     site (`apply_locked_record`), which has exactly one caller
//!     (`rematerialize_one_record`), whose incoming record is a snapshot of
//!     *this* device's own committed rows. The bound no longer sits on a peer
//!     trust boundary at all, and a propagated record carries an empty vector
//!     anyway. Its honest-growth-is-a-no-op property keeps unit coverage in
//!     `version_vector.rs`. Note this assertion was flag-gated (first seed
//!     only, and off entirely under a reduced ops budget) — it was that file's
//!     soak dimension, not its core.
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
//! re-sends an idempotent `HeadsAnnounce` every `full_index_resync_interval`.
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
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use dst_support::clock::HarnessClock;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::peer_session::PeerSyncSession;
use yadorilink_sync_core::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_transport::PeerChannel;

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
    state: Arc<SyncState>,
    processor: Arc<LocalChangeProcessor>,
    session: OnceLock<Arc<PeerSyncSession>>,
}

fn setup_device(
    device_id: &str,
    root: PathBuf,
    state: Arc<SyncState>,
    store: Arc<FsBlockStore>,
) -> Arc<Device> {
    let processor = Arc::new(
        LocalChangeProcessor::new(state.clone(), store, device_id.to_string())
            .with_change_emitter(dst_dag_migrate_b2::emitter_for(device_id)),
    );
    Arc::new(Device {
        device_id: device_id.to_string(),
        root,
        state,
        processor,
        session: OnceLock::new(),
    })
}

fn gen_keypair(rng: &mut StdRng) -> (StaticSecret, PublicKey) {
    // `From<[u8; 32]>` rather than `StaticSecret::random_from_rng`: the latter
    // no longer type-checks under `--cfg madsim` after the rand 0.10 bump
    // (boringtun 0.7's x25519-dalek bounds rand_core 0.6 there). Equally
    // deterministic per seed, and consumes the same 32 rng bytes.
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
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
        if let Some(session) = device.session.get() {
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
            if name == yadorilink_sync_core::root_identity::ROOT_MARKER_FILE_NAME {
                continue;
            }
            if let Ok(bytes) = std::fs::read(entry.path()) {
                out.insert(name, bytes);
            }
        }
    }
    out
}

async fn connect(
    rng: &mut StdRng,
    laptop: &Arc<Device>,
    store_l: Arc<FsBlockStore>,
    always_on: &Arc<Device>,
    store_a: Arc<FsBlockStore>,
) {
    let (secret_l, public_l) = gen_keypair(rng);
    let (secret_a, public_a) = gen_keypair(rng);
    let socket_l = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_l = socket_l.local_addr().unwrap();
    let addr_a = socket_a.local_addr().unwrap();

    let channel_l = Arc::new(
        PeerChannel::connect(
            secret_l,
            public_a,
            0,
            vec![addr_a],
            yadorilink_transport::TransportHub::from_socket(socket_l, Some(public_l)),
        )
        .await
        .unwrap(),
    );
    let channel_a = Arc::new(
        PeerChannel::connect(
            secret_a,
            public_l,
            1,
            vec![addr_l],
            yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
        )
        .await
        .unwrap(),
    );

    let mut roots_l = HashMap::new();
    roots_l.insert(GROUP_ID.to_string(), laptop.root.clone());
    let session_l = PeerSyncSession::new(
        channel_l,
        laptop.device_id.clone(),
        always_on.device_id.clone(),
        laptop.state.clone(),
        store_l,
        vec![GROUP_ID.to_string()],
        roots_l,
    );
    let mut roots_a = HashMap::new();
    roots_a.insert(GROUP_ID.to_string(), always_on.root.clone());
    let session_a = PeerSyncSession::new(
        channel_a,
        always_on.device_id.clone(),
        laptop.device_id.clone(),
        always_on.state.clone(),
        store_a,
        vec![GROUP_ID.to_string()],
        roots_a,
    );

    laptop.session.set(session_l.clone()).ok();
    always_on.session.set(session_a.clone()).ok();
    let ids = [laptop.device_id.as_str(), always_on.device_id.as_str()];
    dst_dag_migrate_b2::wire_dag_session(&session_l, &ids);
    dst_dag_migrate_b2::wire_dag_session(&session_a, &ids);
    tokio::spawn(session_l.run());
    tokio::spawn(session_a.run());
}

fn content_for(seed: u64, cycle: usize, seq: usize, tag: &str) -> Vec<u8> {
    format!("seed {seed} cycle {cycle} seq {seq} {tag}").into_bytes()
}

async fn run_scenario(seed: u64) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let clock = HarnessClock::from_seed(seed);
    clock.install_as_session_clock();

    let dir_l = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_l = dir_l.path().canonicalize().map_err(|e| e.to_string())?;
    let sdir_l = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_l = Arc::new(FsBlockStore::new(sdir_l.path()).map_err(|e| e.to_string())?);
    let state_l = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    dst_support::link::link_and_start(&state_l, &root_l, GROUP_ID)?;

    let dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_a = dir_a.path().canonicalize().map_err(|e| e.to_string())?;
    let sdir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_a = Arc::new(FsBlockStore::new(sdir_a.path()).map_err(|e| e.to_string())?);
    let state_a = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    dst_support::link::link_and_start(&state_a, &root_a, GROUP_ID)?;

    let laptop = setup_device("device-laptop", root_l.clone(), state_l, store_l.clone());
    let always_on = setup_device("device-always-on", root_a.clone(), state_a, store_a.clone());
    set_partitioned(false);
    connect(&mut rng, &laptop, store_l, &always_on, store_a).await;

    // Startup gate: prove the session is actually up (handshake + a first
    // heads-announce round trip) before the cycles begin. Not part of what this
    // scenario tests -- a failure here is the separately-documented
    // WireGuard-handshake-under-simulated-time livelock, classified as a skip.
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
