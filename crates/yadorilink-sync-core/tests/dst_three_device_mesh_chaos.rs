//! Three-device mesh DST fuzzer -- the two-device harness (`dst_two_device_
//! chaos.rs`) cannot exercise a topology this crate's mesh-forwarding code
//! actually runs against in production: `daemon_state.rs::broadcast_change`
//! fans a forwarded record out to *every* session sharing the group, with
//! no source-peer exclusion, and `peer_session.rs::forward` (~1957) hands a
//! resolved/adopted record to that fan-out with no origin/seen marker of
//! its own. The only thing standing between that and an actual forward
//! loop is `reconcile_one_file`'s `VvOrdering::Equal | After => no-op`
//! (~4160-4161) -- implicit, not an explicit loop guard. A two-device
//! harness can never reach that fan-out code at all (`forward_tx`'s only
//! "other" session in a 2-node graph is the one the record came from), so
//! it has never actually exercised this path. This scenario builds the
//! smallest topology that does: three devices, fully meshed (three direct
//! edges: A-B, B-C, A-C), each device wired with **two** peer sessions and
//! a device-level forwarder that mirrors `broadcast_change`'s exact shape
//! (fan every adopted/resolved record out to *all* of this device's
//! sessions, unconditionally).
//!
//! Even though every pair is directly connected (no graph-theoretic
//! "multi-hop"), the forwarder still produces genuine multi-path delivery:
//! a solo write on A reaches B both directly (A-B) *and* indirectly (A-C,
//! then C's forwarder relays it to B over C-B) -- two arrival paths for
//! the same record, racing each other under simulated scheduling. That is
//! exactly the shape this file exists to fuzz: does the second arrival
//! ever get treated as "new" instead of a no-op (duplication/loop), and
//! does a genuine concurrent write on the *third*, otherwise uninvolved
//! device (C) ever diverge from what A and B settle on (missed/duplicated
//! propagation, or a conflict-copy name the two independent pairwise
//! resolutions computed differently)?
//!
//! Reuses `dst_support::case_ir` (`Op`, `ContentTable`, the `Case`
//! corpus-replay shape) and `dst_support::oracle::GlobalOracle` verbatim --
//! `GlobalOracle`'s checks already take `devices: &[(&Path, &SyncState)]`,
//! so no oracle changes are needed to check three devices instead of two.
//! The device/session/debounce wiring below is a from-scratch mesh variant
//! of `dst_two_device_chaos.rs`'s `ChaosDevice`/`setup_device`/
//! `connect_sessions` (single-session assumptions throughout there don't
//! generalize), not a copy-paste.

#![cfg(madsim)]

mod dst_support;

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use dst_support::case_ir::{Case, ContentTable, DeviceTimeline, LinkTopology, Op, Topology};
use dst_support::oracle::GlobalOracle;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::debounce::{self, DebounceConfig, FlushPathRequest};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::materialization::{
    cleanup_stale_temp_files, repair_interrupted_materializations,
};
use yadorilink_sync_core::peer_session::{
    set_test_clock_override, PeerSyncSession, PendingLocalChangeFlush,
};
use yadorilink_sync_core::version_vector::{VersionVector, VvOrdering};
use yadorilink_sync_core::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource,
};
use yadorilink_transport::{PeerChannel, TransportMode};

const GROUP_ID: &str = "mesh-chaos-group";
const CANARY_PATH: &str = "startup-canary.bin";
const CANDIDATE_PATHS: [&str; 3] = ["mesh-a.bin", "mesh-b.bin", "mesh-c.bin"];
/// Wider than the two-device harness's `ROUND_SETTLE` (400ms): a solo
/// write here has to settle through *two* hops in the worst case (direct
/// edge + the losing side of the direct-vs-forwarded race), not one.
const ROUND_SETTLE: Duration = Duration::from_millis(700);
const RACE_INNER_DELAY: Duration = Duration::from_millis(20);
const RACE_SETTLE: Duration = Duration::from_millis(900);
/// Extra settle after the second half of a rename (the new-path write),
/// giving both the tombstone's and the fresh write's own mesh-wide
/// propagation a chance to fully finish before the next round's
/// convergence gate is evaluated.
const RENAME_SETTLE: Duration = Duration::from_millis(900);
const DEFAULT_OPS_PER_RUN: usize = 8;
const DEFAULT_VARIATIONS: u64 = 20;
const BASELINE_TIMEOUT_MARKER: &str = "BASELINE_TIMEOUT: ";
const TIME_LIMIT_MARKER: &str = "TIME_LIMIT: ";
const RESOURCE_EXHAUSTION_MARKER: &str = "RESOURCE_EXHAUSTION: ";

/// Comfortably above the two-device harness's own 45s gate: a 3-node mesh
/// has strictly more in-flight forwarding work per round (each adopted
/// record re-enters `send_index_update` on both of the adopting device's
/// sessions), so the same self-echo re-index churn this project has
/// already root-caused (`fix-duplicate-conflict-copy-on-reresolution`) has
/// more opportunities to fire per round here, not fewer.
const ROUND_PROGRESSION_GATE: Duration = Duration::from_secs(75);
const FINAL_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(90);

/// One device in the 3-node mesh. Unlike `dst_two_device_chaos.rs`'s
/// `ChaosDevice` (exactly one peer, exactly one session), this device has
/// **two** neighbor sessions -- `sessions` is populated once, after both
/// of this device's edges are connected, by `connect_mesh`.
struct MeshDevice {
    device_id: String,
    root: PathBuf,
    state: Arc<SyncState>,
    processor: Arc<LocalChangeProcessor>,
    events_tx: tokio::sync::mpsc::Sender<FsChangeEvent>,
    flush_request_tx: tokio::sync::mpsc::Sender<FlushPathRequest>,
    /// This device's session to each of its two neighbors. Broadcasting a
    /// locally-produced (or directly-injected) record to *every* entry
    /// here is this harness's mirror of `link_manager::announce_local_
    /// change` -> `DaemonState::broadcast_change`'s real fan-out shape
    /// (`daemon_state.rs` ~927: every session sharing the group, no
    /// exclusion).
    sessions: OnceLock<Vec<Arc<PeerSyncSession>>>,
}

impl MeshDevice {
    async fn broadcast(
        &self,
        group_id: &str,
        records: Vec<yadorilink_sync_core::types::FileRecord>,
    ) {
        if records.is_empty() {
            return;
        }
        if let Some(sessions) = self.sessions.get() {
            for session in sessions {
                let _ = session.send_index_update(group_id, records.clone()).await;
            }
        }
    }
}

impl PendingLocalChangeFlush for MeshDevice {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let path = self.root.join(rel_path);
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if self
                .flush_request_tx
                .send(FlushPathRequest {
                    path: path.clone(),
                    mode: debounce::FlushMode::ExactPath,
                    reply: reply_tx,
                })
                .await
                .is_err()
            {
                return;
            }
            let found = match tokio::time::timeout(Duration::from_millis(500), reply_rx).await {
                Ok(Ok(found)) => found,
                _ => None,
            };
            let Some((found_path, kind, observed_at)) = found else { return };
            if let Ok(outcome) = self
                .processor
                .process_flush(
                    group_id,
                    &self.root,
                    debounce::DebounceFlush::Paths(vec![(found_path, kind, observed_at)]),
                )
                .await
            {
                self.broadcast(group_id, outcome.records).await;
            }
        })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let path = self.root.join(rel_path);
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if self
                .flush_request_tx
                .send(FlushPathRequest {
                    path,
                    mode: debounce::FlushMode::CaseFoldSibling,
                    reply: reply_tx,
                })
                .await
                .is_err()
            {
                return;
            }
            let found = match tokio::time::timeout(Duration::from_millis(500), reply_rx).await {
                Ok(Ok(found)) => found,
                _ => None,
            };
            let Some((sibling_path, kind, observed_at)) = found else { return };
            if let Ok(outcome) = self
                .processor
                .process_flush(
                    group_id,
                    &self.root,
                    debounce::DebounceFlush::Paths(vec![(sibling_path, kind, observed_at)]),
                )
                .await
            {
                self.broadcast(group_id, outcome.records).await;
            }
        })
    }
}

/// Sets up one device's real watcher/debounce/`LocalChangeProcessor`
/// pipeline -- identical shape to `dst_two_device_chaos.rs`'s
/// `setup_device`, except the flush executor broadcasts to *every*
/// session this device holds (`MeshDevice::broadcast`) instead of a
/// single one.
fn setup_device(
    device_id: &str,
    root: PathBuf,
    sync_state: Arc<SyncState>,
    store: Arc<FsBlockStore>,
) -> Arc<MeshDevice> {
    let processor =
        Arc::new(LocalChangeProcessor::new(sync_state.clone(), store, device_id.to_string()));
    let (flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    let (watch_source, events_tx) = SimulatedFolderWatchSource::new(32);
    let ignore_set =
        Arc::new(yadorilink_sync_core::ignore_patterns::EffectiveIgnoreSet::defaults_only());
    let watcher = watch_source.watch(&root, ignore_set).unwrap();
    let (events_rx, overflowed, guard) = watcher.split();
    Box::leak(Box::new(guard));

    let (flush_tx, mut flush_rx) =
        tokio::sync::mpsc::channel(debounce::DEFAULT_EXECUTOR_CHANNEL_CAPACITY);
    let (_flush_all_request_tx, flush_all_request_rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(debounce::run_debouncer(
        DebounceConfig::default(),
        events_rx,
        flush_tx,
        overflowed,
        flush_request_rx,
        flush_all_request_rx,
    ));

    let device = Arc::new(MeshDevice {
        device_id: device_id.to_string(),
        root: root.clone(),
        state: sync_state,
        processor: processor.clone(),
        events_tx,
        flush_request_tx,
        sessions: OnceLock::new(),
    });

    let executor_device = device.clone();
    tokio::spawn(async move {
        while let Some(flush) = flush_rx.recv().await {
            match executor_device
                .processor
                .process_flush(GROUP_ID, &executor_device.root, flush)
                .await
            {
                Ok(outcome) => {
                    if std::env::var("DST_MESH_DEBUG").is_ok() && !outcome.records.is_empty() {
                        for r in &outcome.records {
                            eprintln!(
                                "  [{}] self-echo flush -> broadcast: path={:?} deleted={}",
                                executor_device.device_id, r.path, r.deleted
                            );
                        }
                    }
                    executor_device.broadcast(GROUP_ID, outcome.records).await;
                }
                Err(e) => {
                    if std::env::var("DST_MESH_DEBUG").is_ok() {
                        eprintln!("  [{}] process_flush ERROR: {e}", executor_device.device_id);
                    }
                }
            }
        }
    });

    device
}

async fn poll_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !condition() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn gen_keypair(rng: &mut StdRng) -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(rng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Connects one direct edge between two devices, returning each side's
/// new session (not yet registered into either device's `sessions` list,
/// not yet forwarding-wired, not yet running -- `connect_mesh` does all
/// three once every edge exists). Mirrors `dst_two_device_chaos.rs`'s
/// `connect_sessions` pairwise-connection shape exactly, generalized to
/// be called once per edge instead of once per whole scenario.
#[allow(clippy::too_many_arguments)]
async fn connect_edge(
    rng: &mut StdRng,
    device_a: &Arc<MeshDevice>,
    state_a: Arc<SyncState>,
    store_a: Arc<FsBlockStore>,
    forward_tx_a: tokio::sync::mpsc::UnboundedSender<(
        String,
        yadorilink_sync_core::types::FileRecord,
    )>,
    device_b: &Arc<MeshDevice>,
    state_b: Arc<SyncState>,
    store_b: Arc<FsBlockStore>,
    forward_tx_b: tokio::sync::mpsc::UnboundedSender<(
        String,
        yadorilink_sync_core::types::FileRecord,
    )>,
) -> (Arc<PeerSyncSession>, Arc<PeerSyncSession>) {
    let (secret_a, public_a) = gen_keypair(rng);
    let (secret_b, public_b) = gen_keypair(rng);
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let channel_a = Arc::new(
        PeerChannel::connect(
            TransportMode::DirectOnly,
            secret_a,
            public_b,
            0,
            None,
            vec![addr_b],
            Some(socket_a),
        )
        .await
        .unwrap(),
    );
    let channel_b = Arc::new(
        PeerChannel::connect(
            TransportMode::DirectOnly,
            secret_b,
            public_a,
            1,
            None,
            vec![addr_a],
            Some(socket_b),
        )
        .await
        .unwrap(),
    );

    let mut sync_roots_a = HashMap::new();
    sync_roots_a.insert(GROUP_ID.to_string(), device_a.root.clone());
    let session_a = PeerSyncSession::new_with_forwarding(
        channel_a,
        device_a.device_id.clone(),
        device_b.device_id.clone(),
        state_a,
        store_a,
        vec![GROUP_ID.to_string()],
        sync_roots_a,
        Some(forward_tx_a),
        None,
    );

    let mut sync_roots_b = HashMap::new();
    sync_roots_b.insert(GROUP_ID.to_string(), device_b.root.clone());
    let session_b = PeerSyncSession::new_with_forwarding(
        channel_b,
        device_b.device_id.clone(),
        device_a.device_id.clone(),
        state_b,
        store_b,
        vec![GROUP_ID.to_string()],
        sync_roots_b,
        Some(forward_tx_b),
        None,
    );

    (session_a, session_b)
}

/// Wires the full 3-node mesh: three direct edges (A-B, B-C, A-C), one
/// device-level forward channel per device (shared by *both* of that
/// device's sessions -- matching `daemon_state.rs`'s single `sessions`
/// map draining into one `broadcast_change` per device, not one per
/// session), and starts every session's `run()` loop.
///
/// The forwarder task spawned per device here is the harness-level stand-in
/// the task brief calls for: it is the direct analogue of `broadcast_
/// change`'s `for (peer_id, session) in sessions { session.send_index_
/// update(...) }` loop -- fed by *either* neighbor's adopted/resolved
/// record (via `forward_tx`, shared across both of this device's
/// sessions), fanned back out to *all* of this device's sessions
/// unconditionally, including the one the record just arrived from. That
/// last part is deliberate, not an oversight: production's `broadcast_
/// change` has no source-peer exclusion either (see this file's own doc
/// comment) -- reproducing that exactly is the point.
async fn connect_mesh(
    rng: &mut StdRng,
    device_a: &Arc<MeshDevice>,
    state_a: Arc<SyncState>,
    store_a: Arc<FsBlockStore>,
    device_b: &Arc<MeshDevice>,
    state_b: Arc<SyncState>,
    store_b: Arc<FsBlockStore>,
    device_c: &Arc<MeshDevice>,
    state_c: Arc<SyncState>,
    store_c: Arc<FsBlockStore>,
) {
    let (fwd_tx_a, mut fwd_rx_a) = tokio::sync::mpsc::unbounded_channel();
    let (fwd_tx_b, mut fwd_rx_b) = tokio::sync::mpsc::unbounded_channel();
    let (fwd_tx_c, mut fwd_rx_c) = tokio::sync::mpsc::unbounded_channel();

    let (session_ab_a, session_ab_b) = connect_edge(
        rng,
        device_a,
        state_a.clone(),
        store_a.clone(),
        fwd_tx_a.clone(),
        device_b,
        state_b.clone(),
        store_b.clone(),
        fwd_tx_b.clone(),
    )
    .await;
    let (session_bc_b, session_bc_c) = connect_edge(
        rng,
        device_b,
        state_b.clone(),
        store_b.clone(),
        fwd_tx_b.clone(),
        device_c,
        state_c.clone(),
        store_c.clone(),
        fwd_tx_c.clone(),
    )
    .await;
    let (session_ac_a, session_ac_c) = connect_edge(
        rng, device_a, state_a, store_a, fwd_tx_a, device_c, state_c, store_c, fwd_tx_c,
    )
    .await;

    device_a.sessions.set(vec![session_ab_a.clone(), session_ac_a.clone()]).ok();
    device_b.sessions.set(vec![session_ab_b.clone(), session_bc_b.clone()]).ok();
    device_c.sessions.set(vec![session_bc_c.clone(), session_ac_c.clone()]).ok();

    for session in [&session_ab_a, &session_ac_a] {
        session.set_pending_local_change_flush(device_a.clone());
    }
    for session in [&session_ab_b, &session_bc_b] {
        session.set_pending_local_change_flush(device_b.clone());
    }
    for session in [&session_bc_c, &session_ac_c] {
        session.set_pending_local_change_flush(device_c.clone());
    }

    let fwd_device_a = device_a.clone();
    tokio::spawn(async move {
        while let Some((group_id, record)) = fwd_rx_a.recv().await {
            fwd_device_a.broadcast(&group_id, vec![record]).await;
        }
    });
    let fwd_device_b = device_b.clone();
    tokio::spawn(async move {
        while let Some((group_id, record)) = fwd_rx_b.recv().await {
            fwd_device_b.broadcast(&group_id, vec![record]).await;
        }
    });
    let fwd_device_c = device_c.clone();
    tokio::spawn(async move {
        while let Some((group_id, record)) = fwd_rx_c.recv().await {
            fwd_device_c.broadcast(&group_id, vec![record]).await;
        }
    });

    for session in
        [session_ab_a, session_ab_b, session_bc_b, session_bc_c, session_ac_a, session_ac_c]
    {
        tokio::spawn(session.run());
    }
}

fn device_has_live_record(device: &MeshDevice, path: &str) -> bool {
    device.state.get_file(GROUP_ID, path).ok().flatten().map(|r| !r.deleted).unwrap_or(false)
}

fn stamp_deterministic_mtime(path: &Path, virtual_now_nanos: i64) -> Result<(), String> {
    let modified = std::time::UNIX_EPOCH + Duration::from_nanos(virtual_now_nanos as u64);
    let file = std::fs::File::options().write(true).open(path).map_err(|e| e.to_string())?;
    file.set_times(std::fs::FileTimes::new().set_modified(modified)).map_err(|e| e.to_string())
}

async fn deliver_local_write(
    device: &Arc<MeshDevice>,
    path: &str,
    content: Vec<u8>,
    virtual_now_nanos: i64,
) -> Result<(), String> {
    let full_path = device.root.join(path);
    std::fs::write(&full_path, &content).map_err(|e| e.to_string())?;
    stamp_deterministic_mtime(&full_path, virtual_now_nanos)?;
    device
        .events_tx
        .send(FsChangeEvent { path: full_path, kind: FsChangeKind::CreatedOrModified })
        .await
        .map_err(|_| "watcher channel closed early".to_string())
}

fn remove_file_if_present(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

async fn deliver_local_delete(device: &Arc<MeshDevice>, path: &str) -> Result<(), String> {
    remove_file_if_present(&device.root.join(path))?;
    device
        .events_tx
        .send(FsChangeEvent { path: device.root.join(path), kind: FsChangeKind::Removed })
        .await
        .map_err(|_| "watcher channel closed early".to_string())
}

/// Directly indexes a change on `device` and broadcasts it to every
/// session `device` holds -- the "other side" of a race round, mirroring
/// `dst_two_device_chaos.rs`'s `apply_and_push` (bypassing this device's
/// own watcher/debounce, since it isn't the side whose pending-accumulator
/// timing this round is controlling), generalized to broadcast instead of
/// a single `send_index_update`.
async fn apply_and_push(
    device: &Arc<MeshDevice>,
    path: &str,
    kind: FsChangeKind,
) -> Result<LocalChangeOutcome, String> {
    let outcome = device
        .processor
        .process_event(
            GROUP_ID,
            &device.root,
            &FsChangeEvent { path: device.root.join(path), kind },
        )
        .await
        .map_err(|e| e.to_string())?;
    if let LocalChangeOutcome::FileChanged(record) = &outcome {
        device.broadcast(GROUP_ID, vec![record.clone()]).await;
    }
    Ok(outcome)
}

fn content_for(seed: u64, round: usize, device_id: &str, tag: &str) -> Vec<u8> {
    format!("seed {seed} round {round} {tag} {device_id}").into_bytes()
}

/// Waits until all three devices' indexed version vector for `path`
/// compare as `Equal` (or none of them has any record yet) -- the 3-way
/// generalization of `dst_two_device_chaos.rs`'s `converge_path`, needed
/// for exactly the same reason: without proving a genuinely converged
/// common base before a race round, a legitimate `VvOrdering::Before`
/// outcome (this round's baseline hadn't finished propagating from a
/// prior round) is indistinguishable from real data loss.
async fn converge_path_all3(devices: [&MeshDevice; 3], path: &str) -> (bool, Duration) {
    let start = tokio::time::Instant::now();
    let mut converged = false;
    poll_until(ROUND_PROGRESSION_GATE, || {
        let versions: Vec<Option<VersionVector>> = devices
            .iter()
            .map(|d| d.state.get_file(GROUP_ID, path).ok().flatten().map(|r| r.version))
            .collect();
        converged = match (&versions[0], &versions[1], &versions[2]) {
            (None, None, None) => true,
            (Some(a), Some(b), Some(c)) => {
                a.compare(b) == VvOrdering::Equal && a.compare(c) == VvOrdering::Equal
            }
            _ => false,
        };
        converged
    })
    .await;
    (converged, start.elapsed())
}

fn corpus_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/dst_corpus/three_device_mesh_chaos_cases.jsonl")
}

fn load_corpus_cases() -> Vec<Case> {
    let Ok(contents) = std::fs::read_to_string(corpus_path()) else { return Vec::new() };
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn record_failing_case(case: &Case) {
    let path = corpus_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(json) = serde_json::to_string(case) else { return };
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{json}");
    }
}

/// One round's shape, chosen by a weighted die roll in `run_scenario`.
enum RoundKind {
    /// Scenario (a): one device writes/deletes solo; all three must
    /// converge (exercises multi-path delivery -- direct edge *and*
    /// forwarded-via-the-third-device -- even though the graph is fully
    /// meshed).
    Solo,
    /// Scenario (b): two devices concurrently write/delete the same path;
    /// the third, uninvolved device must still converge to the identical
    /// result (same conflict-copy naming, no duplicate) purely via
    /// forwarding.
    Race,
    /// Scenario (c): one device renames a path (tombstone-old +
    /// fresh-write-new, `local_change.rs`'s real decomposition, each
    /// under its own `path_lock`) while a second device concurrently
    /// writes/deletes the old or new path; the third device is a
    /// bystander that must still converge.
    RenameRace,
}

fn choose_round_kind(rng: &mut StdRng) -> RoundKind {
    match rng.gen_range(0..10) {
        0..=3 => RoundKind::Solo,
        4..=6 => RoundKind::Race,
        _ => RoundKind::RenameRace,
    }
}

async fn run_scenario(seed: u64, ops_per_run: usize) -> Result<(), String> {
    let _ = tracing_subscriber::fmt::try_init();
    let mut rng = StdRng::seed_from_u64(seed);

    let root_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_a = root_dir_a.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_a = Arc::new(FsBlockStore::new(store_dir_a.path()).map_err(|e| e.to_string())?);
    let state_a = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    state_a.add_link(&root_a.to_string_lossy(), GROUP_ID).map_err(|e| e.to_string())?;

    let root_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_b = root_dir_b.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_b = Arc::new(FsBlockStore::new(store_dir_b.path()).map_err(|e| e.to_string())?);
    let state_b = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    state_b.add_link(&root_b.to_string_lossy(), GROUP_ID).map_err(|e| e.to_string())?;

    let root_dir_c = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_c = root_dir_c.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_c = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_c = Arc::new(FsBlockStore::new(store_dir_c.path()).map_err(|e| e.to_string())?);
    let state_c = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    state_c.add_link(&root_c.to_string_lossy(), GROUP_ID).map_err(|e| e.to_string())?;

    let device_a = setup_device("device-a", root_a.clone(), state_a.clone(), store_a.clone());
    let device_b = setup_device("device-b", root_b.clone(), state_b.clone(), store_b.clone());
    let device_c = setup_device("device-c", root_c.clone(), state_c.clone(), store_c.clone());
    let recovery_store_a = store_a.clone();
    let recovery_store_b = store_b.clone();
    let recovery_store_c = store_c.clone();

    connect_mesh(
        &mut rng, &device_a, state_a, store_a, &device_b, state_b, store_b, &device_c, state_c,
        store_c,
    )
    .await;

    // Startup gate: A's write must reach *both* B and C before the
    // randomized rounds begin -- mirrors `dst_two_device_chaos.rs`'s
    // canary, extended to prove all three edges (and both forwarders) are
    // actually live, not just the direct A-B/A-C edges.
    std::fs::write(root_a.join(CANARY_PATH), b"canary").map_err(|e| e.to_string())?;
    device_a
        .events_tx
        .send(FsChangeEvent {
            path: root_a.join(CANARY_PATH),
            kind: FsChangeKind::CreatedOrModified,
        })
        .await
        .map_err(|_| "device A's watcher channel closed early".to_string())?;
    poll_until(Duration::from_secs(15), || {
        std::fs::read(root_b.join(CANARY_PATH)).map(|c| c == b"canary").unwrap_or(false)
            && std::fs::read(root_c.join(CANARY_PATH)).map(|c| c == b"canary").unwrap_or(false)
    })
    .await;
    let canary_ok =
        std::fs::read(root_b.join(CANARY_PATH)).map(|c| c == b"canary").unwrap_or(false)
            && std::fs::read(root_c.join(CANARY_PATH)).map(|c| c == b"canary").unwrap_or(false);
    if !canary_ok {
        return Err(format!(
            "{BASELINE_TIMEOUT_MARKER}device B and/or C never adopted the startup canary within the \
             poll timeout -- the same WireGuard-handshake-under-simulated-time livelock \
             dst_peer_reconcile_race.rs/dst_two_device_chaos.rs already document, not a bug in this \
             scenario"
        ));
    }

    let mut content_table = ContentTable::default();
    let mut next_content_id: u64 = 0;
    content_table.insert(next_content_id, b"canary".to_vec());
    next_content_id += 1;
    let mut oracle = GlobalOracle::new();
    let mut recorded_ops: Vec<(usize, u64, Op)> = Vec::new();
    let mut path_baseline: HashMap<String, VersionVector> = HashMap::new();
    let debug = std::env::var("DST_MESH_DEBUG").is_ok();

    let devices_arr = [device_a.as_ref(), device_b.as_ref(), device_c.as_ref()];
    let device_by_idx = |idx: usize| -> &Arc<MeshDevice> {
        match idx {
            0 => &device_a,
            1 => &device_b,
            _ => &device_c,
        }
    };

    let mut virtual_now_nanos: i64 = (seed as i64).wrapping_mul(1_000_000_000);
    set_test_clock_override(virtual_now_nanos);

    for round in 0..ops_per_run {
        virtual_now_nanos = virtual_now_nanos.wrapping_add(1_000_000_000);
        set_test_clock_override(virtual_now_nanos);
        let path = CANDIDATE_PATHS[rng.gen_range(0..CANDIDATE_PATHS.len())].to_string();
        let kind = choose_round_kind(&mut rng);

        match kind {
            RoundKind::Solo => {
                let (converged, elapsed) = converge_path_all3(devices_arr, &path).await;
                oracle.record_round_convergence_latency(&path, elapsed);
                if !converged {
                    return Err(format!(
                        "seed {seed}: round {round}, path {path} never converged across all three \
                         devices within the poll timeout before a solo round -- treated as a failure"
                    ));
                }
                let device_idx = rng.gen_range(0..3);
                let device = device_by_idx(device_idx);
                let do_delete = rng.gen_bool(0.2) && device_has_live_record(device, &path);
                if debug {
                    eprintln!(
                        "seed {seed} round {round}: solo {} on device-{device_idx} path={path}",
                        if do_delete { "delete" } else { "write" }
                    );
                }
                if do_delete {
                    deliver_local_delete(device, &path).await?;
                    tokio::time::sleep(ROUND_SETTLE).await;
                    let mut version = path_baseline.get(&path).cloned().unwrap_or_default();
                    version.increment(&device.device_id);
                    path_baseline.insert(path.clone(), version.clone());
                    oracle.record_delete(&path, device_idx, version);
                    recorded_ops.push((
                        device_idx,
                        round as u64,
                        Op::Delete { path: path.clone() },
                    ));
                } else {
                    let content = content_for(seed, round, &device.device_id, "solo-write");
                    deliver_local_write(device, &path, content.clone(), virtual_now_nanos).await?;
                    tokio::time::sleep(ROUND_SETTLE).await;
                    let content_id = next_content_id;
                    next_content_id += 1;
                    content_table.insert(content_id, content);
                    let mut version = path_baseline.get(&path).cloned().unwrap_or_default();
                    version.increment(&device.device_id);
                    path_baseline.insert(path.clone(), version.clone());
                    oracle.record_write(&path, device_idx, content_id, version);
                    recorded_ops.push((
                        device_idx,
                        round as u64,
                        Op::Write { path: path.clone(), content_id },
                    ));
                }
            }
            RoundKind::Race => {
                let (converged, elapsed) = converge_path_all3(devices_arr, &path).await;
                oracle.record_round_convergence_latency(&path, elapsed);
                if !converged {
                    return Err(format!(
                        "seed {seed}: round {round}, path {path} never converged across all three \
                         devices within the poll timeout before a race round -- treated as a failure"
                    ));
                }
                let mut idxs = [0usize, 1, 2];
                // Fisher-Yates-lite: shuffle 3 elements via 2 swaps so
                // (x, y) are a uniformly random ordered distinct pair and
                // the leftover index is the uninvolved bystander.
                if rng.gen_bool(0.5) {
                    idxs.swap(0, 1);
                }
                if rng.gen_bool(0.5) {
                    idxs.swap(1, 2);
                }
                let (x_idx, y_idx) = (idxs[0], idxs[1]);
                let x = device_by_idx(x_idx);
                let y = device_by_idx(y_idx);
                if debug {
                    eprintln!("seed {seed} round {round}: race x=device-{x_idx} y=device-{y_idx} path={path} (bystander=device-{})", idxs[2]);
                }

                let base = path_baseline.get(&path).cloned().unwrap_or_default();
                let x_content = content_for(seed, round, &x.device_id, "race-x");
                let mut x_version = base.clone();
                x_version.increment(&x.device_id);
                let x_content_id = next_content_id;
                next_content_id += 1;
                content_table.insert(x_content_id, x_content.clone());
                oracle.record_write(&path, x_idx, x_content_id, x_version.clone());
                recorded_ops.push((
                    x_idx,
                    round as u64,
                    Op::Write { path: path.clone(), content_id: x_content_id },
                ));

                deliver_local_write(x, &path, x_content.clone(), virtual_now_nanos).await?;
                tokio::time::sleep(RACE_INNER_DELAY).await;

                virtual_now_nanos = virtual_now_nanos.wrapping_add(100_000_000);
                set_test_clock_override(virtual_now_nanos);

                let y_deletes = rng.gen_bool(0.3) && device_has_live_record(y, &path);
                let mut y_version = base.clone();
                y_version.increment(&y.device_id);
                if y_deletes {
                    remove_file_if_present(&y.root.join(&path))?;
                    apply_and_push(y, &path, FsChangeKind::Removed).await?;
                    oracle.record_delete(&path, y_idx, y_version.clone());
                    recorded_ops.push((y_idx, round as u64, Op::Delete { path: path.clone() }));
                } else {
                    let y_content = content_for(seed, round, &y.device_id, "race-y");
                    let y_path = y.root.join(&path);
                    std::fs::write(&y_path, &y_content).map_err(|e| e.to_string())?;
                    stamp_deterministic_mtime(&y_path, virtual_now_nanos)?;
                    apply_and_push(y, &path, FsChangeKind::CreatedOrModified).await?;
                    let y_content_id = next_content_id;
                    next_content_id += 1;
                    content_table.insert(y_content_id, y_content);
                    oracle.record_write(&path, y_idx, y_content_id, y_version.clone());
                    recorded_ops.push((
                        y_idx,
                        round as u64,
                        Op::Write { path: path.clone(), content_id: y_content_id },
                    ));
                }
                path_baseline.insert(path.clone(), x_version.merge(&y_version));
                tokio::time::sleep(RACE_SETTLE).await;
            }
            RoundKind::RenameRace => {
                let (converged, elapsed) = converge_path_all3(devices_arr, &path).await;
                oracle.record_round_convergence_latency(&path, elapsed);
                if !converged {
                    return Err(format!(
                        "seed {seed}: round {round}, path {path} never converged across all three \
                         devices within the poll timeout before a rename-race round -- treated as a \
                         failure"
                    ));
                }
                let renamer_idx = rng.gen_range(0..3);
                let renamer = device_by_idx(renamer_idx);

                if !device_has_live_record(renamer, &path) {
                    // Nothing to rename yet on this device -- fall back to
                    // a plain solo write, same reasoning as
                    // `dst_two_device_chaos.rs`'s solo-delete fallback:
                    // don't record a no-op that never reached the
                    // watcher/debounce boundary at all.
                    let content =
                        content_for(seed, round, &renamer.device_id, "rename-fallback-write");
                    deliver_local_write(renamer, &path, content.clone(), virtual_now_nanos).await?;
                    tokio::time::sleep(ROUND_SETTLE).await;
                    let content_id = next_content_id;
                    next_content_id += 1;
                    content_table.insert(content_id, content);
                    let mut version = path_baseline.get(&path).cloned().unwrap_or_default();
                    version.increment(&renamer.device_id);
                    path_baseline.insert(path.clone(), version.clone());
                    oracle.record_write(&path, renamer_idx, content_id, version);
                    recorded_ops.push((
                        renamer_idx,
                        round as u64,
                        Op::Write { path: path.clone(), content_id },
                    ));
                    continue;
                }

                let new_path = format!("{path}.renamed-{seed}-{round}");
                // Fresh name -- should trivially converge as None/None/None
                // on all three, but prove it rather than assume it (a
                // prior round could in principle have collided on an
                // unlucky seed/round pairing).
                let (new_converged, _) = converge_path_all3(devices_arr, &new_path).await;
                if !new_converged {
                    return Err(format!(
                        "seed {seed}: round {round}, rename target {new_path} was not a fresh, \
                         converged (empty) path on all three devices -- scenario bug, not a product \
                         violation"
                    ));
                }

                // Racer: a different device than the renamer; bystander is
                // the third. `race_target` picks whether the racer
                // contests the tombstone-old half or the fresh-write-new
                // half of the rename -- both are real, independent
                // `path_lock` scopes per `local_change.rs`'s rename
                // decomposition (~571-585), so both are worth fuzzing.
                let racer_idx = (renamer_idx + 1 + rng.gen_range(0..2)) % 3;
                let racer = device_by_idx(racer_idx);
                let race_old = rng.gen_bool(0.5);
                if debug {
                    eprintln!(
                        "seed {seed} round {round}: rename-race renamer=device-{renamer_idx} \
                         racer=device-{racer_idx} old={path} new={new_path} race_target={}",
                        if race_old { "old" } else { "new" }
                    );
                }

                let base = path_baseline.get(&path).cloned().unwrap_or_default();

                // Step A: tombstone the old path (mirrors `local_change.
                // rs`'s `Removed` branch -- a real per-path debounce/
                // dispatch, independently lock-scoped from step B below).
                deliver_local_delete(renamer, &path).await?;
                tokio::time::sleep(RACE_INNER_DELAY).await;
                virtual_now_nanos = virtual_now_nanos.wrapping_add(100_000_000);
                set_test_clock_override(virtual_now_nanos);

                let mut old_tombstone_version = base.clone();
                old_tombstone_version.increment(&renamer.device_id);

                if race_old {
                    let racer_deletes = rng.gen_bool(0.3) && device_has_live_record(racer, &path);
                    let mut racer_version = base.clone();
                    racer_version.increment(&racer.device_id);
                    if racer_deletes {
                        remove_file_if_present(&racer.root.join(&path))?;
                        apply_and_push(racer, &path, FsChangeKind::Removed).await?;
                        oracle.record_delete(&path, racer_idx, racer_version.clone());
                        recorded_ops.push((
                            racer_idx,
                            round as u64,
                            Op::Delete { path: path.clone() },
                        ));
                    } else {
                        let racer_content =
                            content_for(seed, round, &racer.device_id, "rename-race-old");
                        let racer_path = racer.root.join(&path);
                        std::fs::write(&racer_path, &racer_content).map_err(|e| e.to_string())?;
                        stamp_deterministic_mtime(&racer_path, virtual_now_nanos)?;
                        apply_and_push(racer, &path, FsChangeKind::CreatedOrModified).await?;
                        let racer_content_id = next_content_id;
                        next_content_id += 1;
                        content_table.insert(racer_content_id, racer_content);
                        oracle.record_write(
                            &path,
                            racer_idx,
                            racer_content_id,
                            racer_version.clone(),
                        );
                        recorded_ops.push((
                            racer_idx,
                            round as u64,
                            Op::Write { path: path.clone(), content_id: racer_content_id },
                        ));
                    }
                    oracle.record_delete(&path, renamer_idx, old_tombstone_version.clone());
                    recorded_ops.push((
                        renamer_idx,
                        round as u64,
                        Op::Delete { path: path.clone() },
                    ));
                    path_baseline.insert(path.clone(), old_tombstone_version.merge(&racer_version));
                } else {
                    // Racer targets the *new* path instead -- not touched
                    // yet by the renamer, so its own baseline for
                    // `new_path` starts empty; propagate the tombstone's
                    // settle before moving on regardless.
                    oracle.record_delete(&path, renamer_idx, old_tombstone_version.clone());
                    recorded_ops.push((
                        renamer_idx,
                        round as u64,
                        Op::Delete { path: path.clone() },
                    ));
                    path_baseline.insert(path.clone(), old_tombstone_version);
                }
                tokio::time::sleep(RACE_SETTLE).await;

                // Step B: fresh write at the new path (mirrors `local_
                // change.rs`'s `CreatedOrModified` branch for the
                // just-vacated name -- a second, independent `path_lock`
                // scope from step A).
                let new_content = content_for(seed, round, &renamer.device_id, "rename-race-new");
                if !race_old {
                    deliver_local_write(renamer, &new_path, new_content.clone(), virtual_now_nanos)
                        .await?;
                    tokio::time::sleep(RACE_INNER_DELAY).await;
                    virtual_now_nanos = virtual_now_nanos.wrapping_add(100_000_000);
                    set_test_clock_override(virtual_now_nanos);

                    let mut new_write_version = VersionVector::new();
                    new_write_version.increment(&renamer.device_id);
                    let racer_deletes = false; // new_path never had content to delete yet
                    let _ = racer_deletes;
                    let racer_content =
                        content_for(seed, round, &racer.device_id, "rename-race-new-racer");
                    let racer_path = racer.root.join(&new_path);
                    std::fs::write(&racer_path, &racer_content).map_err(|e| e.to_string())?;
                    stamp_deterministic_mtime(&racer_path, virtual_now_nanos)?;
                    apply_and_push(racer, &new_path, FsChangeKind::CreatedOrModified).await?;
                    let racer_content_id = next_content_id;
                    next_content_id += 1;
                    content_table.insert(racer_content_id, racer_content);
                    let mut racer_version = VersionVector::new();
                    racer_version.increment(&racer.device_id);

                    let new_content_id = next_content_id;
                    next_content_id += 1;
                    content_table.insert(new_content_id, new_content);
                    oracle.record_write(
                        &new_path,
                        renamer_idx,
                        new_content_id,
                        new_write_version.clone(),
                    );
                    recorded_ops.push((
                        renamer_idx,
                        round as u64,
                        Op::Write { path: new_path.clone(), content_id: new_content_id },
                    ));
                    oracle.record_write(
                        &new_path,
                        racer_idx,
                        racer_content_id,
                        racer_version.clone(),
                    );
                    recorded_ops.push((
                        racer_idx,
                        round as u64,
                        Op::Write { path: new_path.clone(), content_id: racer_content_id },
                    ));
                    path_baseline.insert(new_path.clone(), new_write_version.merge(&racer_version));
                } else {
                    deliver_local_write(renamer, &new_path, new_content.clone(), virtual_now_nanos)
                        .await?;
                    tokio::time::sleep(ROUND_SETTLE).await;
                    let new_content_id = next_content_id;
                    next_content_id += 1;
                    content_table.insert(new_content_id, new_content);
                    let mut new_write_version = VersionVector::new();
                    new_write_version.increment(&renamer.device_id);
                    oracle.record_write(
                        &new_path,
                        renamer_idx,
                        new_content_id,
                        new_write_version.clone(),
                    );
                    recorded_ops.push((
                        renamer_idx,
                        round as u64,
                        Op::Write { path: new_path.clone(), content_id: new_content_id },
                    ));
                    path_baseline.insert(new_path.clone(), new_write_version);
                }
                recorded_ops.push((
                    renamer_idx,
                    round as u64,
                    Op::Rename { from: path.clone(), to: new_path.clone() },
                ));
                tokio::time::sleep(RENAME_SETTLE).await;
            }
        }
    }

    let devices: Vec<(&Path, &SyncState)> = vec![
        (device_a.root.as_path(), device_a.state.as_ref()),
        (device_b.root.as_path(), device_b.state.as_ref()),
        (device_c.root.as_path(), device_c.state.as_ref()),
    ];

    let convergence_wait_start = tokio::time::Instant::now();
    let mut converged = false;
    while tokio::time::Instant::now() < convergence_wait_start + FINAL_CONVERGENCE_TIMEOUT {
        if oracle.check_convergence(&devices).is_empty() {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if debug {
        eprintln!(
            "  final convergence: {} after {:?} (bound {FINAL_CONVERGENCE_TIMEOUT:?})",
            if converged { "reached" } else { "NOT reached" },
            tokio::time::Instant::now().saturating_duration_since(convergence_wait_start)
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    for (device, store) in [
        (&device_a, &recovery_store_a),
        (&device_b, &recovery_store_b),
        (&device_c, &recovery_store_c),
    ] {
        let _ = repair_interrupted_materializations(
            &device.state,
            store.as_ref(),
            &device.root,
            GROUP_ID,
        );
        cleanup_stale_temp_files(&device.root);
    }

    if debug {
        for (root, _) in &devices {
            let entries: Vec<String> = std::fs::read_dir(root)
                .map(|rd| {
                    rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect()
                })
                .unwrap_or_default();
            eprintln!("  final tree on {}: {entries:?}", root.display());
        }
    }

    let mut violations = Vec::new();
    if !converged {
        violations.push(dst_support::oracle::Violation {
            kind: dst_support::oracle::ViolationKind::Convergence,
            path: None,
            content_ids: Vec::new(),
            devices: Vec::new(),
            detail: format!(
                "did not reach cross-device (3-way) convergence within {FINAL_CONVERGENCE_TIMEOUT:?} \
                 of virtual time after the last round"
            ),
        });
    }
    violations.extend(oracle.check_convergence(&devices));
    violations.extend(oracle.check_no_loss(&content_table, &devices));
    violations.extend(oracle.check_conflict_copy_accounting(&content_table, &devices, GROUP_ID));
    violations.extend(oracle.check_no_corruption(&content_table, &devices));
    violations.extend(oracle.check_structural(GROUP_ID, &devices));

    for slow in oracle.check_convergence_promptness(Duration::from_secs(5)) {
        eprintln!("  PROMPTNESS: {slow}");
    }

    if debug {
        for v in &violations {
            eprintln!("  VIOLATION: {v}");
        }
    }
    if !violations.is_empty() {
        let mut workload: HashMap<usize, Vec<(u64, Op)>> = HashMap::new();
        for (device_idx, round, op) in recorded_ops {
            workload.entry(device_idx).or_default().push((round, op));
        }
        let case = Case {
            seed,
            topology: Topology {
                device_count: 3,
                links: vec![
                    LinkTopology { group_id: GROUP_ID.to_string(), initial_online: true },
                    LinkTopology { group_id: GROUP_ID.to_string(), initial_online: true },
                    LinkTopology { group_id: GROUP_ID.to_string(), initial_online: true },
                ],
            },
            workload: (0..3)
                .map(|device_index| DeviceTimeline {
                    device_index,
                    ops: workload.remove(&device_index).unwrap_or_default(),
                })
                .collect(),
            fault_schedule: Vec::new(),
            content_table,
        };
        record_failing_case(&case);
        return Err(dst_support::oracle::format_violations(seed, &violations));
    }
    Ok(())
}

fn run_in_madsim(seed: u64, ops_per_run: usize) -> Result<(), String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    // Generous margin above `FINAL_CONVERGENCE_TIMEOUT` (90s) plus rounds'
    // own settle time: a 3-node mesh has more forwarding hops per round
    // than the two-device harness, so its own known ~30s hydration-
    // timeout churn (`fix-duplicate-conflict-copy-on-reresolution`) has
    // more chances to fire per run, not fewer.
    rt.set_time_limit(Duration::from_secs(180));
    rt.set_allow_system_thread(true);
    rt.block_on(run_scenario(seed, ops_per_run)).map_err(|e| {
        if e.starts_with(BASELINE_TIMEOUT_MARKER) || e.contains(&format!("seed {seed}")) {
            e
        } else {
            format!("seed {seed}: {e}")
        }
    })
}

/// Runs one seed, converting a `time limit exceeded` panic and an OS
/// thread-creation-ceiling `WouldBlock` into classifiable `Err`s instead of
/// letting either unwind straight through the sweep and abort every
/// remaining seed in the batch -- mirrors `dst_two_device_chaos.rs`'s
/// `run_seed_catching_time_limit` exactly (same two known, already-
/// documented infra flakes; this scenario opens *three* `SyncState`s and
/// *six* `PeerChannel`s per seed instead of two/one, so the resource-
/// exhaustion ceiling is reached at a proportionally lower cumulative seed
/// count -- irrelevant at this file's small default sweep size).
fn run_seed_catching_time_limit(seed: u64, ops_per_run: usize) -> Result<(), String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_in_madsim(seed, ops_per_run)
    })) {
        Ok(result) => result,
        Err(panic_payload) => {
            let msg = panic_payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic_payload.downcast_ref::<&str>().map(|s| s.to_string()))
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

/// This file's one network-touching `#[test]` fn -- deliberately just one,
/// sequential over many seeds, matching the madsim network-isolation
/// constraint every `dst_*.rs` scenario in this crate already documents
/// (simulated network state isn't safe across more than one network-
/// touching `#[test]` fn per binary, concurrent *or* sequential).
#[test]
fn three_device_mesh_chaos_scenario() {
    let variations: u64 = std::env::var("DST_VARIATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_VARIATIONS);
    let ops_per_run: usize = std::env::var("DST_MESH_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_OPS_PER_RUN);
    let base_seed: u64 =
        std::env::var("DST_BASE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0xC4A0_5000);

    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut skipped_baseline = 0;
    let mut skipped_time_limit = 0;
    let mut skipped_resource_exhaustion = 0;
    let mut failures = Vec::new();

    for case in load_corpus_cases() {
        match run_seed_catching_time_limit(case.seed, ops_per_run) {
            Ok(()) => {}
            Err(e) if e.starts_with(BASELINE_TIMEOUT_MARKER) => skipped_baseline += 1,
            Err(e) if e.starts_with(TIME_LIMIT_MARKER) => skipped_time_limit += 1,
            Err(e) if e.starts_with(RESOURCE_EXHAUSTION_MARKER) => skipped_resource_exhaustion += 1,
            Err(e) => failures.push(format!("[corpus replay] {e}")),
        }
    }

    for i in 0..variations {
        let seed = base_seed.wrapping_add(i);
        match run_seed_catching_time_limit(seed, ops_per_run) {
            Ok(()) => {}
            Err(e) if e.starts_with(BASELINE_TIMEOUT_MARKER) => skipped_baseline += 1,
            Err(e) if e.starts_with(TIME_LIMIT_MARKER) => skipped_time_limit += 1,
            Err(e) if e.starts_with(RESOURCE_EXHAUSTION_MARKER) => skipped_resource_exhaustion += 1,
            Err(e) => failures.push(e),
        }
    }
    std::panic::set_hook(previous_hook);

    let skipped = skipped_baseline + skipped_time_limit + skipped_resource_exhaustion;
    assert!(
        failures.is_empty(),
        "{}/{variations} mesh chaos variations found an oracle violation (skipped {skipped_baseline} \
         on baseline timeout, {skipped_time_limit} on the madsim time limit, \
         {skipped_resource_exhaustion} on OS thread-creation exhaustion):\n{}\n\
         (reproduce one with DST_BASE_SEED=<seed> DST_VARIATIONS=1 cargo test ... \
         three_device_mesh_chaos_scenario, then narrow to run_scenario(seed, ops) directly)",
        failures.len(),
        failures.join("\n---\n")
    );
    assert!(
        skipped < variations,
        "every seed hit BASELINE_TIMEOUT -- nothing was actually exercised"
    );
}
