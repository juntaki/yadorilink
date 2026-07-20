//! Network-fault two-device DST fuzzer: extends `dst_two_device_chaos.rs`'s
//! real two-`PeerSyncSession` harness with madsim network loss, latency /
//! reorder, and a timed full partition/heal window. The older scenario's
//! `fault_schedule` is intentionally always empty; this one makes network
//! faults the thing under test.
//!
//! Both devices run the real watcher-boundary/debounce/`LocalChangeProcessor`
//! pipeline with `PendingLocalChangeFlush` wired (the guard is always on
//! here — this scenario is about finding new bugs against the
//! *production-representative* configuration, not re-proving the specific
//! fixed bug `dst_peer_reconcile_race.rs` already covers with the guard
//! toggled off/on). Local changes propagate to the peer over the
//! change-history DAG, the way production does once a device has a signing
//! key: each device's `LocalChangeProcessor` carries a signed `ChangeEmitter`,
//! so every accepted `process_flush`/`process_event` result also appends a
//! signed change to the history DAG in the same transaction as its index
//! write, and the committing device announces its new heads
//! (`announce_local_commit`). The peer's `run()` loop diffs those heads against
//! its own store, requests only the ancestry it is missing, and materializes
//! the same converged state — so conflict copies are computed locally on each
//! side from the shared change set rather than re-broadcast (the daemon-level
//! pause/receive-only/status-push bits are out of this crate's scope, matching
//! this whole harness's precedent of reproducing only the sync-core-relevant
//! slice of production wiring).
//!
//! Invariant bookkeeping: each round writes to one of a small pool of
//! candidate paths, either solo (one device, then a settle window ample
//! for local dispatch + propagation to complete before the next round —
//! so it cleanly supersedes whatever was on that path before) or racing
//! (mirroring `dst_peer_reconcile_race.rs`'s race shape: one device's
//! edit sits undispatched while the other's independent, causally-later
//! change arrives). A path's *active* event set — the event(s) that must
//! still be discoverable, live or as a conflict-copy, by the end of the
//! run — is simply overwritten by each new round that touches that path:
//! a solo round's one event becomes the sole active entry (the prior
//! round's entries are legitimately, cleanly superseded); a racing
//! round's two events both become active (neither may be silently lost,
//! since both are genuinely concurrent from the system's perspective).
//! `converge_path` proves that "genuinely concurrent" premise before
//! every round (see its own doc comment) — without it, a path reused
//! across several rounds can have its two devices' local causal state
//! genuinely diverge (only best-effort, not verified, cross-device
//! propagation between rounds), making a legitimate `VvOrdering::Before`
//! outcome indistinguishable from real data loss.

#![cfg(madsim)]

mod dst_dag_migrate_b2;
mod dst_support;

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use dst_support::case_ir::{
    Case, ContentTable, DeviceTimeline, Fault, FaultPlan, LinkTopology, NetFault, Op, Topology,
};
use dst_support::clock::HarnessClock;
use dst_support::oracle::GlobalOracle;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::debounce::{self, DebounceConfig, FlushPathRequest};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::peer_session::{PeerSyncSession, PendingLocalChangeFlush};
use yadorilink_sync_core::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource,
};
use yadorilink_transport::PeerChannel;

const GROUP_ID: &str = "dst-chaos-group";
const CANARY_PATH: &str = "startup-canary.bin";
const CANDIDATE_PATHS: [&str; 3] = ["chaos-a.bin", "chaos-b.bin", "chaos-c.bin"];
/// Comfortably above `DebounceConfig::DEFAULT_QUIET_PERIOD` (300ms) plus
/// margin for the flush -> index -> heads-announce -> peer-pull
/// chain, so a solo round's write is fully settled everywhere it's going
/// to reach before the next round starts — what makes it safe to treat a
/// solo round as *cleanly* superseding whatever a prior round left active
/// on the same path.
const ROUND_SETTLE: Duration = Duration::from_millis(400);
/// Mirrors `dst_peer_reconcile_race.rs`'s race timing exactly: long enough
/// for the racing device's own watcher event to register as pending in
/// its debounce accumulator, short enough that it hasn't dispatched yet.
const RACE_INNER_DELAY: Duration = Duration::from_millis(20);
const RACE_SETTLE: Duration = Duration::from_millis(500);
const DEFAULT_OPS_PER_RUN: usize = 8;
const DEFAULT_VARIATIONS: u64 = 32;
const BASELINE_TIMEOUT_MARKER: &str = "BASELINE_TIMEOUT: ";

#[derive(Debug, Clone)]
struct FaultProfile {
    steady_loss: f64,
    latency_min: Duration,
    latency_max: Duration,
    partition_start: Duration,
    partition_duration: Duration,
}

impl FaultProfile {
    fn from_seed(seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed ^ 0x9E37_79B9_7F4A_7C15);
        let steady_loss = rng.random_range(5..=30) as f64 / 100.0;
        let min_ms = rng.random_range(15..=80);
        let max_ms = min_ms + rng.random_range(40..=180);
        let partition_start = Duration::from_millis(rng.random_range(20..=80));
        let partition_duration = Duration::from_millis(rng.random_range(900..=1800));
        Self {
            steady_loss,
            latency_min: Duration::from_millis(min_ms),
            latency_max: Duration::from_millis(max_ms),
            partition_start,
            partition_duration,
        }
    }

    fn describe(&self) -> String {
        format!(
            "steady_loss={:.0}%, latency={:?}..{:?}, partition_start={:?}, partition_duration={:?}",
            self.steady_loss * 100.0,
            self.latency_min,
            self.latency_max,
            self.partition_start,
            self.partition_duration
        )
    }

    fn fault_schedule(&self) -> Vec<(u64, Fault)> {
        vec![
            (0, Fault::Net(NetFault::Drop)),
            (0, Fault::Net(NetFault::Delay { millis: self.latency_max.as_millis() as u64 })),
            (0, Fault::Net(NetFault::Reorder)),
            (
                self.partition_start.as_millis() as u64,
                Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }),
            ),
            (
                (self.partition_start + self.partition_duration).as_millis() as u64,
                Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 }),
            ),
        ]
    }
}

/// This scenario's `PendingLocalChangeFlush` -- identical in role to
/// `dst_peer_reconcile_race.rs`'s `SimDevice`, but always wired on both
/// devices here (see this file's doc comment for why: finding new bugs
/// against the production-representative, guard-always-on configuration,
/// not re-toggling a known fix).
struct ChaosDevice {
    device_id: String,
    root: PathBuf,
    state: Arc<SyncState>,
    processor: Arc<LocalChangeProcessor>,
    events_tx: tokio::sync::mpsc::Sender<FsChangeEvent>,
    flush_request_tx: tokio::sync::mpsc::Sender<FlushPathRequest>,
    session: OnceLock<Arc<PeerSyncSession>>,
}

impl PendingLocalChangeFlush for ChaosDevice {
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
                if !outcome.records.is_empty() {
                    if let Some(session) = self.session.get() {
                        // The emitter appended the signed change during
                        // `process_flush`; announce the new heads so the peer
                        // pulls it over the DAG.
                        let _ = session.announce_local_commit(group_id).await;
                    }
                }
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
                if !outcome.records.is_empty() {
                    if let Some(session) = self.session.get() {
                        // Emitter appended the signed change; announce heads so
                        // the peer pulls it over the DAG.
                        let _ = session.announce_local_commit(group_id).await;
                    }
                }
            }
        })
    }
}

/// Sets up one device's real watcher-boundary/debounce/`LocalChangeProcessor`
/// pipeline, with the executor forwarding every non-empty flush result to
/// this device's (not-yet-connected) session the same way
/// `link_manager::announce_local_change` -> `DaemonState::broadcast_change`
/// does in production for a send-receive link.
fn setup_device(
    device_id: &str,
    root: PathBuf,
    sync_state: Arc<SyncState>,
    store: Arc<FsBlockStore>,
) -> Arc<ChaosDevice> {
    let processor = Arc::new(
        LocalChangeProcessor::new(sync_state.clone(), store, device_id.to_string())
            .with_change_emitter(dst_dag_migrate_b2::emitter_for(device_id)),
    );
    let (flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    let (watch_source, events_tx) = SimulatedFolderWatchSource::new(32);
    let ignore_set =
        Arc::new(yadorilink_sync_core::ignore_patterns::EffectiveIgnoreSet::defaults_only());
    let watcher = watch_source.watch(&root, ignore_set).unwrap();
    let (events_rx, overflowed, guard) = watcher.split();
    Box::leak(Box::new(guard)); // kept alive for the scenario's process lifetime

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

    let device = Arc::new(ChaosDevice {
        device_id: device_id.to_string(),
        root: root.clone(),
        state: sync_state,
        processor: processor.clone(),
        events_tx,
        flush_request_tx,
        session: OnceLock::new(),
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
                    if std::env::var("DST_CHAOS_DEBUG").is_ok() && !outcome.records.is_empty() {
                        for r in &outcome.records {
                            eprintln!(
                                "  [{}] self-echo flush -> announce_local_commit: path={:?} deleted={}",
                                executor_device.device_id, r.path, r.deleted
                            );
                        }
                    }
                    if !outcome.records.is_empty() {
                        if let Some(session) = executor_device.session.get() {
                            // Emitter appended the signed change during
                            // `process_flush`; announce heads so the peer pulls
                            // it over the DAG (the short-cadence periodic audit
                            // re-drives this under fault).
                            let _ = session.announce_local_commit(GROUP_ID).await;
                        }
                    }
                }
                Err(e) => {
                    if std::env::var("DST_CHAOS_DEBUG").is_ok() {
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

/// PF (fidelity/artifact-reduction) gate relaxation, agmsg investigation
/// 2026-07-09: this bound used to be 5s, which false-failed round
/// progression against the self-echo re-index churn's ~30s hydration-
/// timeout cycle (confirmed production-real, not a harness/madsim
/// artifact). Production has no "N seconds or fail" gate at all -- only
/// eventual consistency -- so this bound only needs to be "comfortably
/// above the slowest legitimate settle path this scenario can hit", not
/// tight. Loosening it does *not* hide the churn's real cost: the caller
/// records the elapsed time into `GlobalOracle::check_convergence_
/// promptness`, which flags (without blocking round progression) any
/// convergence slower than a realistic SLA.
// This is now the *budget*
// `converge_path` hands to the shared `settle_until` primitive, not a
// hand-rolled poll gate -- the 45s rationale above still governs the value.
const ROUND_SETTLE_BUDGET: Duration = Duration::from_secs(45);

/// The "realistic SLA" `check_convergence_promptness` flags against --
/// comfortably above `ROUND_SETTLE`/`RACE_SETTLE`'s own settle windows
/// plus round-trip margin, well below the self-echo re-index churn's
/// ~30s hydration-timeout cycle, so a normal round's ordinary settle
/// never flags while that churn reliably does.
const CONVERGENCE_PROMPTNESS_SLA: Duration = Duration::from_secs(3);

/// Waits until both devices' indexed version vector for `path` compare
/// as `Equal` (or neither has any record at all yet) -- i.e. a genuinely
/// converged, common causal base for this path on both sides.
///
/// This is what makes a `Race` round's "both sides' edits are genuinely
/// concurrent, so both must survive" assumption actually true: two edits
/// made from a *converged* common base are provably concurrent (neither
/// can have observed the other), exactly `dst_peer_reconcile_race.rs`'s
/// one-time baseline-adoption wait, just repeated before every round
/// here since this scenario reuses a small path pool across many rounds
/// (still-open "superseded by a causally-later *remote*
/// write" checker gap, closed *for this scenario* the same way task
/// 5.1/5.2 closed it: proving a converged base rather than generalizing
/// `dst_support`'s checker to compare version vectors directly). Without
/// this, a round can legitimately race from two *already-diverged*
/// bases (a prior round's propagation hadn't finished settling), making
/// a genuine, correct `VvOrdering::Before` outcome indistinguishable
/// from the bug this whole harness exists to catch -- confirmed the hard
/// way (see this file's git history) by chasing what first looked like a
/// real finding back to exactly this gap.
async fn converge_path(
    device_a: &ChaosDevice,
    device_b: &ChaosDevice,
    path: &str,
) -> (bool, Duration) {
    let outcome = dst_support::settle::settle_until(ROUND_SETTLE_BUDGET, || {
        let a = device_a.state.get_file(GROUP_ID, path).ok().flatten();
        let b = device_b.state.get_file(GROUP_ID, path).ok().flatten();
        match (&a, &b) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                a.version.compare(&b.version)
                    == yadorilink_sync_core::version_vector::VvOrdering::Equal
            }
            _ => false,
        }
    })
    .await;
    (outcome.converged, outcome.elapsed)
}

fn gen_keypair(rng: &mut StdRng) -> (StaticSecret, PublicKey) {
    // Prereq: derive the boringtun secret
    // from 32 seed-driven bytes rather than `StaticSecret::random_from_rng`,
    // which no longer type-checks under `--cfg madsim` after the committed rand
    // 0.10 bump (boringtun 0.7's x25519-dalek 2.0.1 bounds rand_core 0.6 on
    // `random_from_rng`). `From<[u8; 32]>` needs no rng trait and is equally
    // deterministic per seed; test-only. `fill` consumes exactly 32 rng bytes
    // like the old `random_from_rng`'s internal `fill_bytes`, so the per-seed
    // workload stream is undisturbed (only the ephemeral key value is derived).
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

async fn connect_sessions(
    rng: &mut StdRng,
    device_a: &Arc<ChaosDevice>,
    state_a: Arc<SyncState>,
    store_a: Arc<FsBlockStore>,
    device_b: &Arc<ChaosDevice>,
    state_b: Arc<SyncState>,
    store_b: Arc<FsBlockStore>,
) {
    let (secret_a, public_a) = gen_keypair(rng);
    let (secret_b, public_b) = gen_keypair(rng);
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();

    let channel_a = Arc::new(
        PeerChannel::connect(
            secret_a,
            public_b,
            0,
            vec![addr_b],
            yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
        )
        .await
        .unwrap(),
    );
    let channel_b = Arc::new(
        PeerChannel::connect(
            secret_b,
            public_a,
            1,
            vec![addr_a],
            yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
        )
        .await
        .unwrap(),
    );

    // On the change-history DAG a conflict copy needs no daemon-style
    // `broadcast_change` re-fan-out: each device materializes the same conflict
    // copy locally from the shared change set (both sides pull every change via
    // the heads-announce -> change-request -> change-batch loop), so the legacy
    // forwarding channel (`new_with_forwarding` + a re-`send_index_update`
    // loop) is dropped. Both devices run the plain session and converge by
    // pulling each other's announced heads.
    let mut sync_roots_a = HashMap::new();
    sync_roots_a.insert(GROUP_ID.to_string(), device_a.root.clone());
    let session_a = PeerSyncSession::new(
        channel_a,
        device_a.device_id.clone(),
        device_b.device_id.clone(),
        state_a,
        store_a,
        vec![GROUP_ID.to_string()],
        sync_roots_a,
    );

    let mut sync_roots_b = HashMap::new();
    sync_roots_b.insert(GROUP_ID.to_string(), device_b.root.clone());
    let session_b = PeerSyncSession::new(
        channel_b,
        device_b.device_id.clone(),
        device_a.device_id.clone(),
        state_b,
        store_b,
        vec![GROUP_ID.to_string()],
        sync_roots_b,
    );

    device_a.session.set(session_a.clone()).ok();
    device_b.session.set(session_b.clone()).ok();
    session_a.set_pending_local_change_flush(device_a.clone());
    session_b.set_pending_local_change_flush(device_b.clone());

    // Pin both devices' verifying keys (each admits the other's signed changes)
    // and shorten the heads-announce cadence so DAG catch-up re-drives promptly
    // under packet loss / a partition window.
    let device_ids = [device_a.device_id.as_str(), device_b.device_id.as_str()];
    dst_dag_migrate_b2::wire_dag_session(&session_a, &device_ids);
    dst_dag_migrate_b2::wire_dag_session(&session_b, &device_ids);

    tokio::spawn(session_a.run());
    tokio::spawn(session_b.run());
}

fn device_has_live_record(device: &ChaosDevice, path: &str) -> bool {
    device.state.get_file(GROUP_ID, path).ok().flatten().map(|r| !r.deleted).unwrap_or(false)
}

async fn deliver_local_write(
    device: &Arc<ChaosDevice>,
    path: &'static str,
    content: Vec<u8>,
    clock: &HarnessClock,
) -> Result<(), String> {
    let full_path = device.root.join(path);
    // Gap A: `fs_ops::write` writes and stamps the mtime through the shared
    // `HarnessClock` in one step -- no local `stamp_deterministic_mtime`.
    dst_support::fs_ops::write(clock, &full_path, &content)?;
    device
        .events_tx
        .send(FsChangeEvent { path: full_path, kind: FsChangeKind::CreatedOrModified })
        .await
        .map_err(|_| "watcher channel closed early".to_string())
}

async fn deliver_local_delete(device: &Arc<ChaosDevice>, path: &'static str) -> Result<(), String> {
    // `fs_ops::remove` tolerates a concurrent removal (the spawned
    // `PeerSyncSession::run`/debounce tasks share this simulated runtime
    // and can race on the same file) exactly as the old local
    // `remove_file_if_present` did.
    dst_support::fs_ops::remove(&device.root.join(path))?;
    device
        .events_tx
        .send(FsChangeEvent { path: device.root.join(path), kind: FsChangeKind::Removed })
        .await
        .map_err(|_| "watcher channel closed early".to_string())
}

/// Directly indexes a change on `device` and pushes it to `device`'s
/// session -- the "other side" of a race round, mirroring
/// `dst_peer_reconcile_race.rs`'s `device_b_process_event` (bypassing
/// this device's own watcher/debounce, since it isn't the side whose
/// pending-accumulator timing this round is controlling).
async fn apply_and_push(
    device: &Arc<ChaosDevice>,
    path: &'static str,
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
    if let LocalChangeOutcome::FileChanged(_record) = &outcome {
        if let Some(session) = device.session.get() {
            // `process_event` (emitter set) appended the signed change; announce
            // heads so the peer pulls it over the DAG.
            session.announce_local_commit(GROUP_ID).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(outcome)
}

fn content_for(seed: u64, round: usize, device_id: &str, tag: &str) -> Vec<u8> {
    format!("seed {seed} round {round} {tag} {device_id}").into_bytes()
}

/// one serialized `Case` per
/// line (JSON Lines -- simple to append, simple to read back one Case at
/// a time without parsing the whole file as one JSON array). Mirrors
/// `monkey_chaos.rs`'s `tests/dst_corpus/monkey_chaos_seeds.txt` pattern
/// one level up: that corpus persists bare seeds (fine, since `monkey_
/// chaos.rs`'s generator has stayed stable); this one persists the full
/// `Case` so a promoted failure survives *this* file's generator
/// evolving, by design's stated rationale for the IR.
fn corpus_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/dst_corpus/network_fault_chaos_cases.jsonl")
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

/// Appends `case`'s JSON serialization to the corpus file (creating it/its
/// directory if needed), best-effort -- a failure to persist must not
/// itself panic out of an already-failing scenario.
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

async fn run_scenario(
    seed: u64,
    ops_per_run: usize,
    fault_profile: FaultProfile,
) -> Result<(), String> {
    let _ = tracing_subscriber::fmt::try_init();
    let mut rng = StdRng::seed_from_u64(seed);

    let root_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_a = root_dir_a.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_a = Arc::new(FsBlockStore::new(store_dir_a.path()).map_err(|e| e.to_string())?);
    let state_a = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    dst_support::link::link_and_start(&state_a, &root_a, GROUP_ID)
        .map_err(|e| e.to_string())?;
    let root_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_b = root_dir_b.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_b = Arc::new(FsBlockStore::new(store_dir_b.path()).map_err(|e| e.to_string())?);
    let state_b = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    dst_support::link::link_and_start(&state_b, &root_b, GROUP_ID)
        .map_err(|e| e.to_string())?;
    let device_a = setup_device("device-a", root_a.clone(), state_a.clone(), store_a.clone());
    let device_b = setup_device("device-b", root_b.clone(), state_b.clone(), store_b.clone());
    // PF (fidelity/artifact-reduction) F.2, agmsg investigation 2026-07-09:
    // held past `connect_sessions` moving its own clones, for the recovery
    // sweep at this scenario's quiescence point (see that call site).
    let recovery_store_a = store_a.clone();
    let recovery_store_b = store_b.clone();
    connect_sessions(&mut rng, &device_a, state_a, store_a, &device_b, state_b, store_b).await;

    // Startup gate: prove the connection is actually up (handshake +
    // first heads-announce round trip) before the randomized rounds
    // begin -- not itself part of what this scenario tests, mirroring
    // `dst_peer_reconcile_race.rs`'s baseline-adoption wait.
    std::fs::write(root_a.join(CANARY_PATH), b"canary").map_err(|e| e.to_string())?;
    device_a
        .events_tx
        .send(FsChangeEvent {
            path: root_a.join(CANARY_PATH),
            kind: FsChangeKind::CreatedOrModified,
        })
        .await
        .map_err(|_| "device A's watcher channel closed early".to_string())?;
    poll_until(Duration::from_secs(10), || {
        std::fs::read(root_b.join(CANARY_PATH)).map(|c| c == b"canary").unwrap_or(false)
    })
    .await;
    if !std::fs::read(root_b.join(CANARY_PATH)).map(|c| c == b"canary").unwrap_or(false) {
        return Err(format!(
            "{BASELINE_TIMEOUT_MARKER}device B never adopted the startup canary within the poll \
             timeout -- separately discovered WireGuard-handshake-under-simulated-time livelock, \
             not a bug in this scenario; see dst_peer_reconcile_race.rs's identical finding"
        ));
    }

    madsim::net::NetSim::current()
        .update_config(|cfg| cfg.packet_loss_rate = fault_profile.steady_loss);

    let partition_profile = fault_profile.clone();
    tokio::spawn(async move {
        tokio::time::sleep(partition_profile.partition_start).await;
        let net = madsim::net::NetSim::current();
        net.update_config(|cfg| cfg.packet_loss_rate = 1.0);
        tokio::time::sleep(partition_profile.partition_duration).await;
        net.update_config(|cfg| cfg.packet_loss_rate = partition_profile.steady_loss);
    });

    // retrofit onto the Case
    // IR's `ContentTable` + the multi-device `GlobalOracle` (`dst_support::
    // oracle`), replacing the old device-local `ChaosRun`/`Event`/
    // `EventKind` bookkeeping and its own ad hoc final `write_survives`/
    // `delete_survives` loop entirely -- the oracle's `check_no_loss`
    // supersedes it with a causal-supersession-aware, cross-device check
    // (see `oracle.rs`'s own doc comment for why "every value survives"
    // is the wrong invariant).
    //
    // `path_baseline` is this test driver's own record of each path's
    // latest known merged version -- constructed structurally from what
    // this driver already knows about each round's shape (a solo round
    // always causally supersedes whatever came before; a race round's `x`
    // and `y` are each independently derived from the *same* prior
    // baseline, so they compare as genuinely `Concurrent`), rather than by
    // reading the real `FileRecord` back mid-race: `x`'s write is, by this
    // scenario's whole design, still sitting *pending* in its own
    // debounce accumulator (not yet indexed) at the point `y`'s change
    // arrives, so there is no reliable moment to read `x`'s own resulting
    // version back before its content may be renamed away entirely by
    // conflict resolution.
    let mut content_table = ContentTable::default();
    let mut next_content_id: u64 = 0;
    // The startup canary is scenario-setup infrastructure, not a
    // generated op -- registered so `check_no_corruption` (which treats
    // `content_table` as a complete source of truth for every byte on
    // disk) doesn't flag it as a third, unrecognized value, without
    // giving it full causal (`GlobalOracle::record_write`) tracking it
    // doesn't need.
    content_table.insert(next_content_id, b"canary".to_vec());
    next_content_id += 1;
    let mut oracle = GlobalOracle::new();
    // recorded alongside the
    // oracle bookkeeping above so a failing run can be serialized as a
    // full `Case` (not just a bare seed) for the corpus -- a serialized
    // Case survives generator evolution; a bare seed only replays as long
    // as this file's generator logic is unchanged.
    let mut recorded_ops: Vec<(usize, u64, Op)> = Vec::new();
    let mut path_baseline: HashMap<
        &'static str,
        yadorilink_sync_core::version_vector::VersionVector,
    > = HashMap::new();
    let debug = std::env::var("DST_CHAOS_DEBUG").is_ok();
    let device_idx_of = |device: &ChaosDevice| -> usize {
        if std::ptr::eq(device, device_a.as_ref()) {
            0
        } else {
            1
        }
    };

    // The one seed-derived,
    // strictly-monotonic synthetic "now" for this run, owned by
    // `dst_support::clock::HarnessClock`. `fs_ops::write`/`fs_ops::rename`
    // stamp every tempdir mutation through it (so a forgotten stamp is
    // unrepresentable rather than a reviewer convention -- the pre-migration
    // per-scenario `stamp_deterministic_mtime` state), and every advance keeps
    // the session-visible `now_unix_nanos` override in lockstep. Seeded from
    // `seed` itself (not a constant) so different seeds explore different
    // tie-break regions -- the full rationale the extracted-from
    // `stamp_deterministic_mtime` comment recorded now lives in `clock.rs`.
    let clock = HarnessClock::from_seed(seed);
    clock.install_as_session_clock();

    for round in 0..ops_per_run {
        let path = CANDIDATE_PATHS[rng.random_range(0..CANDIDATE_PATHS.len())];
        let kind_roll = if round == 0 { 9 } else { rng.random_range(0..10) };
        // +1s per round so even a delete-only round (which stamps nothing)
        // still advances the shared timeline; write rounds advance it further
        // via `fs_ops` stamping on every mutation.
        clock.tick_round();
        if debug {
            eprintln!("seed {seed} round {round}: path={path} kind_roll={kind_roll}");
        }
        let (round_converged, round_convergence_elapsed) =
            converge_path(&device_a, &device_b, path).await;
        oracle.record_round_convergence_latency(path, round_convergence_elapsed);
        if !round_converged {
            eprintln!(
                "  NETWORK-FAULT: seed {seed} round {round} path {path} did not converge before \
                 the next op; continuing so final heal/resync oracle decides pass/fail"
            );
        }
        match kind_roll {
            0..=3 => {
                // Solo write (40%): cleanly supersedes this path's prior
                // active event(s).
                let device = if rng.random_bool(0.5) { &device_a } else { &device_b };
                let content = content_for(seed, round, &device.device_id, "solo-write");
                if debug {
                    eprintln!(
                        "  solo-write on {} : {:?}",
                        device.device_id,
                        String::from_utf8_lossy(&content)
                    );
                }
                deliver_local_write(device, path, content.clone(), &clock).await?;
                tokio::time::sleep(ROUND_SETTLE).await;

                let content_id = next_content_id;
                next_content_id += 1;
                content_table.insert(content_id, content);
                let mut version = path_baseline.get(path).cloned().unwrap_or_default();
                version.increment(&device.device_id);
                path_baseline.insert(path, version.clone());
                oracle.record_write(path, device_idx_of(device), content_id, version);
                recorded_ops.push((
                    device_idx_of(device),
                    round as u64,
                    Op::Write { path: path.to_string(), content_id },
                ));
            }
            4..=5 => {
                // Solo delete (20%): only meaningful if this device
                // actually has something to delete -- falls back to a
                // solo write otherwise rather than recording a no-op
                // that never reached the watcher/debounce boundary at
                // all.
                let device = if rng.random_bool(0.5) { &device_a } else { &device_b };
                if device_has_live_record(device, path) {
                    if debug {
                        eprintln!("  solo-delete on {}", device.device_id);
                    }
                    deliver_local_delete(device, path).await?;
                    tokio::time::sleep(ROUND_SETTLE).await;

                    let mut version = path_baseline.get(path).cloned().unwrap_or_default();
                    version.increment(&device.device_id);
                    path_baseline.insert(path, version.clone());
                    oracle.record_delete(path, device_idx_of(device), version);
                    recorded_ops.push((
                        device_idx_of(device),
                        round as u64,
                        Op::Delete { path: path.to_string() },
                    ));
                } else {
                    let content =
                        content_for(seed, round, &device.device_id, "solo-write-fallback");
                    deliver_local_write(device, path, content.clone(), &clock).await?;
                    tokio::time::sleep(ROUND_SETTLE).await;

                    let content_id = next_content_id;
                    next_content_id += 1;
                    content_table.insert(content_id, content);
                    let mut version = path_baseline.get(path).cloned().unwrap_or_default();
                    version.increment(&device.device_id);
                    path_baseline.insert(path, version.clone());
                    oracle.record_write(path, device_idx_of(device), content_id, version);
                    recorded_ops.push((
                        device_idx_of(device),
                        round as u64,
                        Op::Write { path: path.to_string(), content_id },
                    ));
                }
            }
            _ => {
                // Race (40%): `x` gets a genuine local edit sitting
                // undispatched in its own debounce accumulator when
                // `y`'s independent, causally-later change arrives --
                // dst_peer_reconcile_race.rs's exact race shape, just
                // driven many times over randomized path/device/op
                // choices instead of one hand-crafted case.
                let (x, y) = if rng.random_bool(0.5) {
                    (&device_a, &device_b)
                } else {
                    (&device_b, &device_a)
                };
                let x_content = content_for(seed, round, &x.device_id, "race-x");
                if debug {
                    eprintln!("  race: x={} y={}", x.device_id, y.device_id);
                }

                // Both `x` and `y` derive independently from the same
                // pre-race baseline -- genuinely concurrent, neither
                // dominating the other, matching what `resolve_and_apply_
                // conflict` sees regardless of which one this driver
                // happens to apply first.
                let base = path_baseline.get(path).cloned().unwrap_or_default();
                let mut x_version = base.clone();
                x_version.increment(&x.device_id);
                let x_content_id = next_content_id;
                next_content_id += 1;
                content_table.insert(x_content_id, x_content.clone());
                oracle.record_write(path, device_idx_of(x), x_content_id, x_version.clone());
                recorded_ops.push((
                    device_idx_of(x),
                    round as u64,
                    Op::Write { path: path.to_string(), content_id: x_content_id },
                ));

                deliver_local_write(x, path, x_content.clone(), &clock).await?;
                tokio::time::sleep(RACE_INNER_DELAY).await;

                // `y` happens strictly after `x`: the relative ordering that
                // decides the conflict is the version vector (`y_version`
                // below), and y's own `fs_ops::write` advances the shared clock
                // again so its stamped mtime lands strictly after x's -- no
                // hand-tuned +100ms sub-step needed (the per-mutation stamp
                // gives the ordering for free).

                let y_deletes = rng.random_bool(0.3) && device_has_live_record(y, path);
                if debug {
                    eprintln!("  race: y_deletes={y_deletes}");
                }
                let mut y_version = base.clone();
                y_version.increment(&y.device_id);
                if y_deletes {
                    // `process_event` re-derives the effective kind from
                    // a real `symlink_metadata` re-stat regardless of
                    // what `kind` is passed (`local_change.rs`: "the
                    // watcher is a trigger to re-examine a path, not a
                    // source of truth") -- the file must actually be
                    // gone from disk *before* this call, or a `Removed`
                    // event silently turns into a `CreatedOrModified`
                    // re-index of the untouched existing content.
                    dst_support::fs_ops::remove(&y.root.join(path))?;
                    apply_and_push(y, path, FsChangeKind::Removed).await?;
                    oracle.record_delete(path, device_idx_of(y), y_version.clone());
                    recorded_ops.push((
                        device_idx_of(y),
                        round as u64,
                        Op::Delete { path: path.to_string() },
                    ));
                } else {
                    let y_content = content_for(seed, round, &y.device_id, "race-y");
                    let y_path = y.root.join(path);
                    dst_support::fs_ops::write(&clock, &y_path, &y_content)?;
                    apply_and_push(y, path, FsChangeKind::CreatedOrModified).await?;
                    let y_content_id = next_content_id;
                    next_content_id += 1;
                    content_table.insert(y_content_id, y_content);
                    oracle.record_write(path, device_idx_of(y), y_content_id, y_version.clone());
                    recorded_ops.push((
                        device_idx_of(y),
                        round as u64,
                        Op::Write { path: path.to_string(), content_id: y_content_id },
                    ));
                }
                path_baseline.insert(path, x_version.merge(&y_version));
                tokio::time::sleep(RACE_SETTLE).await;
            }
        }
    }

    let devices: Vec<(&Path, &SyncState)> = vec![
        (device_a.root.as_path(), device_a.state.as_ref()),
        (device_b.root.as_path(), device_b.state.as_ref()),
    ];

    // fix (agmsg review,
    // 2026-07-08), now via the shared `dst_support::settle` primitive:
    // the oracle must only ever
    // run at a genuinely converged, quiescent point -- a fixed pre-oracle
    // settle sleep before the last round's propagation has actually finished
    // produces exactly the same "looks like a violation, is really mid-flight"
    // false signal this scenario's own `converge_path` was written to close for
    // the *per-round* gate (see its doc comment's "confirmed the hard way"
    // account) -- this is that same gap, at the *final* check instead of
    // a mid-run one. `settle` polls `check_convergence` itself as the condition
    // (bounded, generous -- oracle #1 wants a real timeout to
    // be a failure, not silently ignored, but also wants the virtual time
    // it took recorded: a few virtual seconds is normal settle, a bound
    // anywhere near `DEFAULT_FULL_INDEX_RESYNC_INTERVAL`'s (~90s) scale is
    // itself a real, separate latency finding worth surfacing, not an
    // artifact).
    // 60s, not a few seconds: `ensure_blocks_present`'s `DEFAULT_HYDRATION_
    // TIMEOUT` (`peer_session.rs`, 30s) is a legitimate, production
    // latency this scenario can hit (confirmed root cause of a real
    // dedup-guard gap in `resolve_and_apply_conflict`, agmsg investigation
    // 2026-07-08) -- convergence taking up to ~30s after that fires is
    // expected, not itself a bug; the bound just needs comfortable margin
    // above it, not to suppress it.
    // Gap B: the shared `settle` primitive polls `check_convergence` on the
    // sim clock and returns the instant it converges. On budget exhaustion it
    // records a non-fatal `SlowConvergence` instead of the old
    // hand-rolled poll loop's hard timeout -- the terminal `check_convergence`
    // below still hard-fails on a genuinely divergent final state.
    const FINAL_CONVERGENCE_BUDGET: Duration = Duration::from_secs(180);
    let outcome = dst_support::settle::settle(&devices, &oracle, FINAL_CONVERGENCE_BUDGET).await;
    let converged = outcome.converged;
    if debug {
        eprintln!(
            "  final convergence: {} after {:?} (budget {FINAL_CONVERGENCE_BUDGET:?})",
            if converged { "reached" } else { "NOT reached" },
            outcome.elapsed
        );
    }
    if let Some(slow) = &outcome.slow_convergence {
        eprintln!("  SLOW-CONVERGENCE: {slow}");
    }

    // PF (fidelity/artifact-reduction) F.2, agmsg investigation 2026-07-09:
    // a real daemon runs `repair_interrupted_materializations` +
    // `cleanup_stale_temp_files` at startup and periodically
    // (`link_manager.rs`) -- this bare-`PeerSyncSession` harness never
    // called either, so an interrupted eager materialize's window
    // (`materialize`'s own `upsert_file_with_origin`-before-`reconstruct_
    // file` ordering, see its doc comment) left a live-but-fileless index
    // row + an orphaned `.yadorilink-tmp.*` file permanently, surfacing as
    // `StructuralIndexDiskMismatch`/`Corruption` violations the same
    // production self-healing sweep would have already cleared before any
    // health check ran against it (seed 3298840595's finding). Run once
    // per device at this scenario's own genuinely-quiescent point --
    // matching daemon fidelity, not masking the underlying materialize-
    // ordering gap (a separate,
    // low-priority hardening item; this only stops it from producing
    // harness-only oracle noise).
    for (device, store) in [(&device_a, &recovery_store_a), (&device_b, &recovery_store_b)] {
        for finding in dst_support::sweep::run_self_healing(
            &device.state,
            store.as_ref(),
            &device.root,
            GROUP_ID,
        ) {
            // Informational `RepairedBySweep`, surfaced (like the
            // promptness findings) so the repair-path exercise stays visible;
            // never folded into the fatal `violations` list.
            eprintln!("  {finding}");
        }
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
        for (id, bytes) in content_table.iter() {
            eprintln!("  content_id {id}: {:?}", String::from_utf8_lossy(bytes));
        }
    }

    let mut violations = Vec::new();
    // No separate hard "did not converge in budget" violation --
    // `settle` above already recorded a non-fatal `SlowConvergence` if the
    // budget was exhausted, and this terminal `check_convergence` hard-fails
    // here if (and only if) the final state is genuinely divergent rather than
    // merely slow. `converged` remains only for the debug print above.
    let _ = converged;
    violations.extend(oracle.check_convergence(&devices));
    violations.extend(oracle.check_no_loss(&content_table, &devices));
    violations.extend(oracle.check_conflict_copy_accounting(&content_table, &devices, GROUP_ID));
    violations.extend(oracle.check_no_corruption(&content_table, &devices, GROUP_ID));
    violations.extend(oracle.check_structural(GROUP_ID, &devices));

    // PF promptness oracle, agmsg investigation 2026-07-09: deliberately
    // *not* folded into `violations` above -- these never gate this run's
    // pass/fail (`ROUND_SETTLE_BUDGET` above already tolerates the
    // self-echo re-index churn's ~30s hydration-timeout cycle; failing
    // the run again here would just re-hide the same cost behind a
    // different violation kind). Always printed (not just under `debug`):
    // this is exactly the "measure it, show it, don't hide it" signal
    // `ROUND_SETTLE_BUDGET`'s own doc comment promises -- a slow-but-
    // eventually-consistent round must stay visible somewhere, or
    // loosening the gate quietly reintroduces the thing fixed
    // (a real cost hidden as a silent pass).
    for slow in oracle.check_convergence_promptness(CONVERGENCE_PROMPTNESS_SLA) {
        eprintln!("  PROMPTNESS: {slow}");
    }

    if debug {
        for v in &violations {
            eprintln!("  VIOLATION: {v}");
        }
    }
    if !violations.is_empty() {
        // persist the full
        // Case (not just the seed) so this failure survives generator
        // evolution in the corpus -- see `record_failing_case`'s doc
        // comment.
        let mut workload: HashMap<usize, Vec<(u64, Op)>> = HashMap::new();
        for (device_idx, round, op) in recorded_ops {
            workload.entry(device_idx).or_default().push((round, op));
        }
        let case = Case {
            seed,
            topology: Topology {
                device_count: 2,
                links: vec![
                    LinkTopology { group_id: GROUP_ID.to_string(), initial_online: true },
                    LinkTopology { group_id: GROUP_ID.to_string(), initial_online: true },
                ],
            },
            workload: (0..2)
                .map(|device_index| DeviceTimeline {
                    device_index,
                    ops: workload.remove(&device_index).unwrap_or_default(),
                })
                .collect(),
            fault_schedule: fault_profile.fault_schedule(),
            content_table,
            fault_plan: FaultPlan::default(),
        };
        record_failing_case(&case);
        return Err(format!(
            "{}\nfault_profile: {}",
            dst_support::oracle::format_violations(seed, &violations),
            fault_profile.describe()
        ));
    }
    Ok(())
}

fn run_in_madsim(seed: u64, ops_per_run: usize) -> Result<(), String> {
    let fault_profile = FaultProfile::from_seed(seed);
    let mut config = madsim::Config::default();
    config.net.packet_loss_rate = 0.0;
    config.net.send_latency = fault_profile.latency_min..fault_profile.latency_max;
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, config);
    // Comfortable margin above `FINAL_CONVERGENCE_BUDGET` (180s) plus the
    // rounds' own settle time -- was raised from the original 60s while
    // investigating a real convergence-latency bug (see that constant's
    // own doc comment); kept above 60s permanently since a genuine,
    // production-legitimate ~30s hydration-timeout retry can now push a
    // run past the old bound without this being a scenario bug.
    rt.set_time_limit(Duration::from_secs(240));
    let profile_for_error = fault_profile.clone();
    rt.block_on(run_scenario(seed, ops_per_run, fault_profile)).map_err(|e| {
        // Uniformly tag every failure with its seed for reproduction,
        // without double-tagging the ones (`BASELINE_TIMEOUT_MARKER`, the
        // convergence-timeout error, the oracle violation report) that
        // already include it, and without burying `BASELINE_TIMEOUT_
        // MARKER`'s recognizable prefix under a "seed N: " prefix.
        if e.starts_with(BASELINE_TIMEOUT_MARKER) || e.contains(&format!("seed {seed}")) {
            e
        } else {
            format!("seed {seed}: {e}\nfault_profile: {}", profile_for_error.describe())
        }
    })
}

/// Prefix marking a seed as hitting `madsim`'s hard 60-simulated-second
/// time limit -- `Runtime::block_on` panics directly rather than
/// returning an `Err` when this happens, so unlike every other outcome
/// this one is caught via `catch_unwind`, not `?`. Classified the same
/// way as `BASELINE_TIMEOUT_MARKER` (a skip, not a scenario failure):
/// empirically, every occurrence found while scaling this scenario's
/// seed count up traced to the same already-documented finding as
/// `dst_peer_reconcile_race.rs`'s `BASELINE_TIMEOUT_MARKER` -- a genuine
/// WireGuard-handshake-under-simulated-time livelock for a specific
/// seed, not a deadlock in this scenario's own logic (isolating each
/// hanging seed with `DST_VARIATIONS=1` never reproduced it standalone,
/// only as part of a larger sequential batch -- consistent with the
/// network-touching-runtime isolation gap both DST peer-session files
/// already document, just manifesting as a livelock instead of state
/// corruption this time).
const TIME_LIMIT_MARKER: &str = "TIME_LIMIT: ";
/// Prefix marking a seed as hitting the OS-level thread-creation ceiling
/// (`EAGAIN`/`WouldBlock` on a `.unwrap`'d `bind`/`connect` call deep
/// in `PeerChannel`/`UdpSocket` setup), not a scenario failure -- the
/// same root cause `dst_watcher_debounce.rs` already documents (r2d2's
/// per-`SyncState` background maintenance thread not being torn down
/// promptly across many sequential `SyncState`s in one process, eventually
/// approaching `ulimit -u`), just hit at a lower cumulative seed count
/// here (empirically ~3000, vs. that file's ~5000) since this scenario
/// opens *two* `SyncState`s per seed instead of one. `DEFAULT_VARIATIONS`
/// (32) and the 300/1000-seed sweeps this scenario was verified against
/// while building it are comfortably below this ceiling; a heat-run/
/// nightly sweep pushing `DST_VARIATIONS` into the low thousands should
/// expect to hit it and treat it as a known, already-understood limit,
/// not a new finding.
const RESOURCE_EXHAUSTION_MARKER: &str = "RESOURCE_EXHAUSTION: ";

/// Runs one seed, converting a `time limit exceeded` panic (see
/// `TIME_LIMIT_MARKER`) into a classifiable `Err` instead of letting it
/// unwind straight through `two_device_chaos_scenario` and abort every
/// remaining seed in the batch -- mirrors `monkey_chaos.rs`'s
/// `catch_unwind` use for the same reason (one bad seed's infra flake
/// shouldn't hide every other seed's result).
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

/// This file's one network-touching `#[test]` fn -- deliberately just
/// one, sequential over many seeds, matching the isolation finding
/// documented in `dst_peer_reconcile_race.rs` (madsim's simulated network
/// state isn't safe across more than one network-touching `#[test]` fn
/// per binary, concurrent *or* sequential). `DST_VARIATIONS`/
/// `DST_CHAOS_OPS` are env-overridable so a heat-run/nightly sweep can
/// scale this up independently of the smaller default used here and in a
/// per-PR run.
#[test]
fn network_fault_chaos_scenario() {
    let variations: u64 = std::env::var("DST_VARIATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_VARIATIONS);
    let ops_per_run: usize = std::env::var("DST_CHAOS_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_OPS_PER_RUN);
    let base_seed: u64 =
        std::env::var("DST_BASE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0xC4A0_5000);

    // Silence the default panic hook for the duration of the sweep --
    // `run_seed_catching_time_limit` already reports a caught time-limit
    // panic through its own classified `Err`, so letting the default
    // hook also print for every such seed would just be noise across a
    // large batch.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    // `CONVERGENCE_TIMEOUT_
    // MARKER` and its `skipped_convergence` skip-classification are
    // retired -- oracle #1 requirement ("a convergence
    // timeout is a FAILURE, not a skip"). A convergence timeout now falls
    // straight through to the `failures` arm below, same as any other
    // scenario error. `BASELINE_TIMEOUT_MARKER`/`TIME_LIMIT_MARKER`/
    // `RESOURCE_EXHAUSTION_MARKER` remain genuine skip categories -- each
    // is a simulated-runtime/session-establishment infra condition
    // unrelated to this scenario's own sync-correctness assertions (see
    // each marker's own doc comment).
    let mut skipped_baseline = 0;
    let mut skipped_time_limit = 0;
    let mut skipped_resource_exhaustion = 0;
    let mut failures = Vec::new();

    // replay every corpus case
    // first, same reasoning as `monkey_chaos.rs`'s `replay_known_failing_
    // seeds` -- a previously-found bug must always be re-checked, not only
    // surface once on whichever sweep happened to find it. One `#[test]`
    // fn per binary (this file's own documented madsim network-isolation
    // constraint), so this can't be a separate test like `monkey_chaos.rs`
    // has room for -- folded into this same sweep instead, using each
    // case's own recorded seed (see `run_scenario`'s doc comment on
    // `record_failing_case` for why the full `Case` is still persisted
    // even though replay is seed-driven for now).
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
        "{}/{variations} network-fault chaos variations found an oracle violation (skipped {skipped_baseline} \
         on baseline timeout, {skipped_time_limit} on the madsim time limit, \
         {skipped_resource_exhaustion} on OS thread-creation exhaustion -- see \
         RESOURCE_EXHAUSTION_MARKER's doc comment if this count is high; a round-convergence \
         timeout is no longer skipped -- it appears among the failures below):\n{}\n\
         (reproduce one with DST_BASE_SEED=<seed> DST_VARIATIONS=1 cargo test ... \
         network_fault_chaos_scenario, then narrow to run_scenario(seed, ops) directly)",
        failures.len(),
        failures.join("\n---\n")
    );
    assert!(
        skipped < variations,
        "every seed hit BASELINE_TIMEOUT -- nothing was actually exercised"
    );
}
