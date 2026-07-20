//! Generated seed-sweep capstone: the self-driving loop that ties the
//! `dst_support` DST toolbox — generator, op-applier, fault schedule, oracle
//! suite, reference model, shrinker, triage, corpus, and coverage — into one
//! end-to-end run.
//!
//! For each seed in a bounded range it:
//!   1. `generator::generate_case(seed)` (guarded by `validate_case`),
//!   2. stands up a real 2-device sync-core harness (the device/session
//!      machinery adapted from `dst_two_device_chaos.rs`),
//!   3. drives the Case's workload in global `(virtual_ts, device)` order,
//!      applying each `Op` through `op_applier::apply_op`, delivering the
//!      resulting watcher event(s), and recording content-bearing ops into
//!      the `GlobalOracle` and the independent `ReferenceModel` inputs,
//!   4. (best-effort) fires the Case's `fault_schedule` via `run_schedule`,
//!   5. settles to quiescence and runs the full oracle suite,
//!   6. on a violation: triages product-bug vs harness-artifact, shrinks a
//!      product bug to a minimal repro, and records the triaged case to a
//!      corpus JSONL that is replayed on the next run, and
//!   7. folds every run into a shared `coverage::CoverageAccumulator` and
//!      prints/emits a coverage summary.
//!
//! Because the driver applies the global op order strictly sequentially,
//! every op lands with a strictly-increasing mtime and a unique reference
//! round, so the reference model's expected converged state is pure
//! last-writer-wins by application order — which is exactly what a
//! sequentially-applied 2-device mesh converges to. That keeps the
//! wrong-winner oracle well-posed without fabricating spurious conflict-copy
//! predictions.
//!
//! Scope of this cut (see the module-level report accompanying it):
//!   - Every `Op` kind is applied to disk through `op_applier` (exercising the
//!     full applier vocabulary), but only content ops (`Write`/`Edit`/`Delete`,
//!     plus the two writes a `ConflictingConcurrent` hint expands into) are
//!     delivered into the live watcher pipeline and recorded into the oracle /
//!     reference-model. Delivering generated structural ops
//!     (`Rename`/`Move`/`Mkdir`/`Rmdir`/`Chmod`) so the mesh reconverges is
//!     deferred — the proven-faithful reference harness drives content ops
//!     only, and so does the mesh-driving path here.
//!   - `>2`-device generated topologies are folded onto the 2-device harness
//!     by remapping `device_index % 2` (the true topology is still recorded
//!     for coverage).
//!   - `fault_schedule` entries are fired through `run_schedule` and their
//!     activation trace surfaced, but the injector plans are NOT yet bound
//!     into the live `PeerChannel`/`FsBlockStore`/`SyncState` — binding them
//!     into the live transport/store is deferred as too invasive for this
//!     cut; faults are therefore scheduled + traced, not injected into live
//!     I/O.
//!   - The sweep gates its pass/fail on `LikelyProductBug` verdicts only;
//!     harness artifacts are recorded and surfaced but do not fail the run,
//!     matching the triage design.
//!
//! `#![cfg(madsim)]`-gated like every DST scenario file.

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
use dst_support::case_ir::{Case, Op};
use dst_support::clock::HarnessClock;
use dst_support::corpus;
use dst_support::coverage::{self, CoverageAccumulator};
use dst_support::fault_schedule::{run_schedule, ScheduledInjectors};
use dst_support::generator;
use dst_support::op_applier;
use dst_support::oracle::{GlobalOracle, Violation, ViolationKind};
use dst_support::reference_model::{self, RefKind, RefOp};
use dst_support::shrinker::{self, ReproOutcome, ShrinkConfig};
use dst_support::triage::{HarnessProfile, TriageVerdict, STANDARD};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::debounce::{self, DebounceConfig, FlushPathRequest};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::LocalChangeProcessor;
use yadorilink_sync_core::peer_session::{PeerSyncSession, PendingLocalChangeFlush};
use yadorilink_sync_core::version_vector::VersionVector;
use yadorilink_sync_core::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource,
};
use yadorilink_transport::PeerChannel;

const GROUP_ID: &str = "dst-generated-sweep-group";
const CANARY_PATH: &str = "startup-canary.bin";
const DEFAULT_VARIATIONS: u64 = 16;
const DEFAULT_BASE_SEED: u64 = 0x5EED_0000;
/// Per-op propagation window: comfortably above the debounce quiet period so
/// a delivered write reaches the peer before the next op is applied. Matches
/// the reference harness's `ROUND_SETTLE`.
const PER_OP_SETTLE: Duration = Duration::from_millis(400);
/// Base terminal settle budget; scaled by the triage profile's
/// `settle_multiplier` for the relaxed replay. 60s, matching the reference
/// harness's `FINAL_CONVERGENCE_BUDGET`: the engine's `DEFAULT_HYDRATION_
/// TIMEOUT` (~30s) is a legitimate production latency a lost-block-fetch
/// recovery can hit, so a shorter budget false-fails a slow-but-eventually-
/// consistent seed as a hard convergence divergence.
const BASE_FINAL_SETTLE: Duration = Duration::from_secs(60);
/// Bounded per-path convergence wait applied before each content op, so the op
/// builds on a converged common base (the reference harness's `converge_path`
/// discipline). Returns fast when the path is already settled.
const PER_PATH_CONVERGE_BUDGET: Duration = Duration::from_secs(30);
/// madsim hard time limit per case run (simulated seconds) — comfortably above
/// a relaxed (4x settle) replay so triage's relaxed probe still completes.
const CASE_TIME_LIMIT: Duration = Duration::from_secs(300);
/// Bounded shrink budget: each replay is a full 2-device network run, so a
/// large budget would dominate sweep wall time. Small-but-useful.
const SHRINK_BUDGET: usize = 12;
/// The floor for the seed-derived harness "now" (~year 2096 in unix nanos):
/// far enough in the future that the harness clock is always ahead of any
/// wall-clock mtime a concurrently-running test stamps (the process-wide
/// clock override is shared), matching the reference scenario's far-future
/// base seed.
const FAR_FUTURE_FLOOR_NANOS: i64 = 4_000_000_000_000_000_000;

const BASELINE_TIMEOUT_MARKER: &str = "BASELINE_TIMEOUT: ";

// ---------------------------------------------------------------------------
// Device / session machinery (adapted from dst_two_device_chaos.rs)
// ---------------------------------------------------------------------------

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
                        // Emitter appended the signed change during
                        // `process_flush`; announce heads so the peer pulls it
                        // over the DAG.
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
    Box::leak(Box::new(guard)); // kept alive for the run's lifetime

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
            if let Ok(outcome) = executor_device
                .processor
                .process_flush(GROUP_ID, &executor_device.root, flush)
                .await
            {
                if !outcome.records.is_empty() {
                    if let Some(session) = executor_device.session.get() {
                        // Emitter appended the signed change during
                        // `process_flush`; announce heads so the peer pulls it
                        // over the DAG (the short-cadence periodic audit
                        // re-drives this under fault).
                        let _ = session.announce_local_commit(GROUP_ID).await;
                    }
                }
            }
        }
    });

    device
}

fn gen_keypair(rng: &mut StdRng) -> (StaticSecret, PublicKey) {
    // `From<[u8; 32]>` (not `random_from_rng`, which no longer type-checks
    // under `--cfg madsim` after the rand 0.10 bump) — equally deterministic
    // per seed and consumes exactly 32 rng bytes.
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

#[allow(clippy::too_many_arguments)]
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

    // On the change-history DAG each device materializes the same conflict
    // copy locally from the shared change set, so the legacy conflict-copy
    // forwarding channel (`new_with_forwarding` + a re-`send_index_update`
    // loop) is dropped: both devices run the plain session and converge by
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

    // Pin both devices' verifying keys and shorten the heads-announce cadence
    // so DAG catch-up re-drives promptly under fault.
    let device_ids = [device_a.device_id.as_str(), device_b.device_id.as_str()];
    dst_dag_migrate_b2::wire_dag_session(&session_a, &device_ids);
    dst_dag_migrate_b2::wire_dag_session(&session_b, &device_ids);

    tokio::spawn(session_a.run());
    tokio::spawn(session_b.run());
}

async fn poll_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !condition() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Waits (bounded) until both devices' indexed version vector for `path`
/// compares `Equal` (or neither has any record yet) — a genuinely converged
/// common base for `path`. Mirrors the reference harness's `converge_path`:
/// applying each op from a converged base is what keeps the mesh reconverging
/// cleanly (and makes a race a genuine race) rather than piling ops onto a
/// still-diverging base. Returns whether it converged within the budget.
async fn converge_path(a: &ChaosDevice, b: &ChaosDevice, path: &str) -> bool {
    dst_support::settle::settle_until(PER_PATH_CONVERGE_BUDGET, || {
        let fa = a.state.get_file(GROUP_ID, path).ok().flatten();
        let fb = b.state.get_file(GROUP_ID, path).ok().flatten();
        match (&fa, &fb) {
            (None, None) => true,
            (Some(x), Some(y)) => {
                x.version.compare(&y.version)
                    == yadorilink_sync_core::version_vector::VvOrdering::Equal
            }
            _ => false,
        }
    })
    .await
    .converged
}

async fn deliver_event(
    device: &ChaosDevice,
    path: PathBuf,
    kind: FsChangeKind,
) -> Result<(), String> {
    device
        .events_tx
        .send(FsChangeEvent { path, kind })
        .await
        .map_err(|_| "watcher channel closed early".to_string())
}

// ---------------------------------------------------------------------------
// The per-case driver: generate-derived Case -> real harness -> oracle suite
// ---------------------------------------------------------------------------

/// Runs one `Case` under `profile`, returning the full oracle-suite violation
/// list observed at quiescence. `Err` marks an infra skip (baseline
/// handshake timeout) that is classified rather than counted as a failure.
async fn drive_case(case: &Case, profile: &HarnessProfile) -> Result<Vec<Violation>, String> {
    let _ = tracing_subscriber::fmt::try_init();
    let seed = case.seed;
    let mut rng = StdRng::seed_from_u64(seed);

    let root_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_a = root_dir_a.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_a = Arc::new(FsBlockStore::new(store_dir_a.path()).map_err(|e| e.to_string())?);
    let recovery_store_a = store_a.clone();
    let state_a = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);

    let root_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_b = root_dir_b.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_b = Arc::new(FsBlockStore::new(store_dir_b.path()).map_err(|e| e.to_string())?);
    let recovery_store_b = store_b.clone();
    let state_b = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);

    let device_a = setup_device("device-0", root_a.clone(), state_a.clone(), store_a.clone());
    let device_b = setup_device("device-1", root_b.clone(), state_b.clone(), store_b.clone());

    connect_sessions(&mut rng, &device_a, state_a, store_a, &device_b, state_b, store_b).await;

    // Startup gate: prove the handshake + first round trip is up before the
    // workload begins. A timeout here is the known WireGuard-under-simulated-
    // time livelock (see dst_two_device_chaos.rs), classified as a skip.
    std::fs::write(root_a.join(CANARY_PATH), b"canary").map_err(|e| e.to_string())?;
    deliver_event(&device_a, root_a.join(CANARY_PATH), FsChangeKind::CreatedOrModified).await?;
    poll_until(Duration::from_secs(10), || {
        std::fs::read(root_b.join(CANARY_PATH)).map(|c| c == b"canary").unwrap_or(false)
    })
    .await;
    if !std::fs::read(root_b.join(CANARY_PATH)).map(|c| c == b"canary").unwrap_or(false) {
        return Err(format!(
            "{BASELINE_TIMEOUT_MARKER}device-1 never adopted the startup canary within the poll \
             timeout"
        ));
    }

    let devices = [device_a.clone(), device_b.clone()];

    // Working content table: the Case's own bytes plus any bytes synthesized
    // for expanded ConflictingConcurrent races. Passed whole to the oracle so
    // every byte that can land on disk is a byte "someone actually wrote".
    let mut content_table = case.content_table.clone();
    let mut next_content_id: u64 =
        content_table.iter().map(|(id, _)| *id).max().map(|m| m + 1).unwrap_or(0);
    // The canary is scenario infra, not a generated op — register its bytes so
    // check_no_corruption doesn't flag it as an unknown value.
    content_table.insert(next_content_id, b"canary".to_vec());
    next_content_id += 1;

    let mut oracle = GlobalOracle::new();
    let mut reference_ops: Vec<RefOp> = Vec::new();
    let mut path_baseline: HashMap<String, VersionVector> = HashMap::new();
    // Strictly-increasing reference round: the driver applies the global order
    // sequentially, so a totally-ordered reference timeline (no two ops share
    // a round) predicts exactly the LWW-by-application-order end state the
    // sequential mesh converges to.
    let mut ref_round: u64 = 0;

    // Pin the harness "now" comfortably in the future, deterministically per
    // seed. The session clock override is process-wide, and a concurrently-
    // running unit test that stamped a file with the real wall clock must
    // never observe a harness "now" in the past (that trips the future-skew /
    // "now >= any past mtime" invariants — the exact interference an early
    // default base seed produced). A far-future floor keeps "now" ahead of any
    // real mtime, exactly as the reference scenario's far-future base seed
    // does; a small seed-derived spread preserves the "different seeds explore
    // different tie-break regions" property `clock.rs` documents.
    let clock = HarnessClock::from_seed(seed);
    let spread = (seed as i64).rem_euclid(1_000_000).wrapping_mul(1_000_000_000);
    let target = FAR_FUTURE_FLOOR_NANOS.wrapping_add(spread);
    let base = clock.now_nanos();
    if target > base {
        clock.advance(target - base);
    }
    clock.install_as_session_clock();

    // Best-effort fault schedule: fire the schedule on the virtual clock and
    // surface its activation trace. The injector plans are not yet bound into
    // the live PeerChannel/BlockStore/SyncState (deferred), so this exercises
    // run_schedule + ScheduledInjectors end-to-end without injecting into live
    // I/O.
    let injectors = ScheduledInjectors::new();
    if !case.fault_schedule.is_empty() {
        let sched = case.fault_schedule.clone();
        let handle = injectors.clone();
        tokio::spawn(async move { run_schedule(sched, handle).await });
    }

    // A scratch mirror that receives EVERY op kind through `op_applier`, in a
    // coherent sequence (so structural ops have their prerequisites), purely to
    // exercise the full applier vocabulary end-to-end. It is never synced and
    // never read by an oracle — keeping structural mutations off the live
    // device roots is what stops a rename/move/rmdir from desyncing the mesh
    // the convergence/structural oracles read.
    let scratch_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let scratch_root = scratch_dir.path().to_path_buf();

    // Global (virtual_ts, device) replay order — identical to the order
    // validate_case checks, with >2-device indices folded onto the 2-device
    // harness.
    let mut ordered: Vec<(u64, usize, &Op)> = Vec::new();
    for tl in &case.workload {
        let dev2 = tl.device_index % 2;
        for (ts, op) in &tl.ops {
            ordered.push((*ts, dev2, op));
        }
    }
    ordered.sort_by_key(|(ts, dev, _)| (*ts, *dev));

    for (_ts, dev_idx, op) in ordered {
        // Expand ConflictingConcurrent into the two concrete per-device ops it
        // is a hint for: a genuine two-device write race on its first path.
        let subops: Vec<(usize, Op)> = match op {
            Op::ConflictingConcurrent { paths } => match paths.first() {
                Some(p) => {
                    let cid_a = next_content_id;
                    content_table.insert(cid_a, format!("cc-{seed}-{ref_round}-a").into_bytes());
                    next_content_id += 1;
                    let cid_b = next_content_id;
                    content_table.insert(cid_b, format!("cc-{seed}-{ref_round}-b").into_bytes());
                    next_content_id += 1;
                    vec![
                        (dev_idx, Op::Write { path: p.clone(), content_id: cid_a }),
                        (dev_idx ^ 1, Op::Write { path: p.clone(), content_id: cid_b }),
                    ]
                }
                None => Vec::new(),
            },
            other => vec![(dev_idx, other.clone())],
        };

        for (d, sub) in subops {
            let device = &devices[d];
            // Content ops build on a converged base (reference `converge_path`
            // discipline): wait for the target path to settle across both
            // devices before mutating it again. Returns fast when already
            // converged; structural ops don't drive the mesh so are exempt.
            if let Op::Write { path, .. } | Op::Edit { path, .. } | Op::Delete { path } = &sub {
                converge_path(&devices[0], &devices[1], path).await;
            }
            clock.next_mtime(); // strictly-increasing mtime for this mutation

            // Exercise the full op_applier vocabulary on the scratch mirror
            // (every op kind, prerequisites in place). The live device roots
            // below receive only the content subset this cut faithfully syncs.
            let _ = op_applier::apply_op(&clock, &scratch_root, &sub, &content_table);

            match &sub {
                Op::Write { path, content_id } | Op::Edit { path, content_id } => {
                    if op_applier::apply_op(&clock, &device.root, &sub, &content_table).is_err() {
                        // A genuine IO race — non-fatal, mirroring the applier's
                        // own NotFound tolerance.
                        continue;
                    }
                    let _ = deliver_event(
                        device,
                        device.root.join(path),
                        FsChangeKind::CreatedOrModified,
                    )
                    .await;
                    let mut version = path_baseline.get(path).cloned().unwrap_or_default();
                    version.increment(&device.device_id);
                    path_baseline.insert(path.clone(), version.clone());
                    oracle.record_write(path, d, *content_id, version);
                    reference_ops.push(RefOp {
                        path: path.clone(),
                        device_id: device.device_id.clone(),
                        round: ref_round,
                        kind: RefKind::Write { content_id: *content_id },
                        mtime_nanos: clock.now_nanos(),
                    });
                    ref_round += 1;
                }
                Op::Delete { path } => {
                    let _ = op_applier::apply_op(&clock, &device.root, &sub, &content_table);
                    let _ =
                        deliver_event(device, device.root.join(path), FsChangeKind::Removed).await;
                    let mut version = path_baseline.get(path).cloned().unwrap_or_default();
                    version.increment(&device.device_id);
                    path_baseline.insert(path.clone(), version.clone());
                    oracle.record_delete(path, d, version);
                    reference_ops.push(RefOp {
                        path: path.clone(),
                        device_id: device.device_id.clone(),
                        round: ref_round,
                        kind: RefKind::Delete,
                        mtime_nanos: clock.now_nanos(),
                    });
                    ref_round += 1;
                }
                // Structural ops (rename/move/chmod/mkdir/rmdir) and the
                // already-expanded ConflictingConcurrent hint were applied to
                // disk above — exercising the full `op_applier` vocabulary —
                // but are deliberately NOT delivered into the live
                // watcher→debounce→index pipeline in this cut. Faithfully
                // reconciling a generated rename/move/dir/chmod stream so the
                // two-device mesh reconverges (and the structural oracle stays
                // clean) is the deferred fidelity work; the proven-faithful
                // reference harness drives only content ops, and so does the
                // mesh-driving path here. See the module-level scope note.
                Op::Rename { .. }
                | Op::Move { .. }
                | Op::Chmod { .. }
                | Op::Mkdir { .. }
                | Op::Rmdir { .. }
                | Op::ConflictingConcurrent { .. } => {}
            }

            tokio::time::sleep(PER_OP_SETTLE).await;
        }
    }

    let devices_ref: Vec<(&Path, &SyncState)> = vec![
        (device_a.root.as_path(), device_a.state.as_ref()),
        (device_b.root.as_path(), device_b.state.as_ref()),
    ];

    let final_budget = BASE_FINAL_SETTLE * profile.settle_multiplier.max(1);
    let outcome = dst_support::settle::settle(&devices_ref, &oracle, final_budget).await;
    let converged = outcome.converged;

    // Production-fidelity self-healing sweep at the quiescent point (repairs
    // interrupted-materialize artifacts a real daemon's periodic task clears),
    // so those do not surface as harness-only structural noise.
    for (device, store) in [(&device_a, &recovery_store_a), (&device_b, &recovery_store_b)] {
        for _finding in dst_support::sweep::run_self_healing(
            &device.state,
            store.as_ref(),
            &device.root,
            GROUP_ID,
        ) {}
    }

    let trace = injectors.trace();
    if !trace.is_empty() {
        eprintln!("  seed {seed}: fault activations (scheduled, not bound to live I/O): {trace:?}");
    }

    let mut violations = Vec::new();
    let convergence_violations = oracle.check_convergence(&devices_ref);
    let is_converged_now = converged && convergence_violations.is_empty();
    violations.extend(convergence_violations);
    violations.extend(oracle.check_no_loss(&content_table, &devices_ref));
    violations.extend(oracle.check_conflict_copy_accounting(
        &content_table,
        &devices_ref,
        GROUP_ID,
    ));
    violations.extend(oracle.check_no_corruption(&content_table, &devices_ref, GROUP_ID));
    violations.extend(oracle.check_structural(GROUP_ID, &devices_ref));
    // Independent reference-model check — only well-posed at a converged,
    // quiescent point. i64::MAX for `now`: this driver never generates
    // adversarial future mtimes, so the future-skew clamp is a no-op.
    if is_converged_now {
        let prediction = reference_model::predict(&reference_ops, i64::MAX);
        violations.extend(reference_model::check_reference_model(
            &prediction,
            &content_table,
            &devices_ref,
        ));
    }

    Ok(violations)
}

// ---------------------------------------------------------------------------
// madsim runtime wrapper + infra-skip classification
// ---------------------------------------------------------------------------

/// The outcome of one classified case run.
enum RunOutcome {
    /// The run completed; carries the oracle-suite violations (possibly empty).
    Violations(Vec<Violation>),
    /// An infra condition unrelated to sync correctness (handshake livelock,
    /// madsim time limit, OS thread-creation ceiling). Not a scenario failure.
    Skip(&'static str),
}

fn run_case_in_madsim(case: &Case, profile: &HarnessProfile) -> Result<Vec<Violation>, String> {
    let mut rt =
        madsim::runtime::Runtime::with_seed_and_config(case.seed, madsim::Config::default());
    rt.set_time_limit(CASE_TIME_LIMIT);
    rt.block_on(drive_case(case, profile))
}

/// Runs one case under `profile`, converting the known infra flakes (a
/// `time limit exceeded` panic or an `EAGAIN`/`WouldBlock` socket failure)
/// into a classifiable `Skip` instead of unwinding through the sweep.
fn run_case_catching(case: &Case, profile: &HarnessProfile) -> RunOutcome {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_case_in_madsim(case, profile)
    })) {
        Ok(Ok(violations)) => RunOutcome::Violations(violations),
        Ok(Err(e)) if e.starts_with(BASELINE_TIMEOUT_MARKER) => RunOutcome::Skip("baseline"),
        // A completed run that errored for a non-skip reason is exceedingly
        // unlikely (drive_case only `?`s on setup + the baseline gate), but
        // surface it as a violation-less run rather than swallowing it.
        Ok(Err(_e)) => RunOutcome::Violations(Vec::new()),
        Err(panic_payload) => {
            let msg = panic_payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic_payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "non-string panic payload".to_string());
            if msg.contains("time limit exceeded") {
                RunOutcome::Skip("time_limit")
            } else if msg.contains("WouldBlock") || msg.contains("Resource temporarily unavailable")
            {
                RunOutcome::Skip("resource_exhaustion")
            } else {
                // An unexpected panic — re-raise so it isn't silently hidden.
                std::panic::resume_unwind(panic_payload);
            }
        }
    }
}

/// The triage/shrink replay adapter: re-run a case under a profile and return
/// its violations (an infra skip during replay yields no violations).
fn replay(case: &Case, profile: &HarnessProfile) -> Vec<Violation> {
    match run_case_catching(case, profile) {
        RunOutcome::Violations(v) => v,
        RunOutcome::Skip(_) => Vec::new(),
    }
}

fn corpus_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dst_corpus/generated_sweep_cases.jsonl")
}

// ---------------------------------------------------------------------------
// The sweep
// ---------------------------------------------------------------------------

struct SeedResult {
    seed: u64,
    /// Gating violations triaged as real product bugs (fail the sweep).
    product_bugs: Vec<Violation>,
    /// Gating violations triaged as harness artifacts (recorded, not gating).
    artifacts: usize,
    /// Content-model-dependent findings (no-loss / conflict-copy accounting /
    /// wrong-winner). These oracles need faithful per-op version-vector and
    /// concurrency modeling that this generic sequential driver does not yet
    /// reproduce, so their findings are advisory in this cut: recorded and
    /// surfaced, never gating.
    advisory: usize,
    skip: Option<&'static str>,
}

/// The two invariants robust to this cut's driving fidelity, so they gate the
/// sweep:
///   - `Convergence`: both devices must agree on every path's version — the
///     headline eventual-consistency property, independent of the driver's
///     bookkeeping.
///   - `Corruption`: every surviving byte string must be one some op actually
///     wrote (the working content table is a complete source of truth), so a
///     fabricated byte is a genuine engine fault.
///
/// The remaining oracles are advisory in this cut (recorded + surfaced, not
/// gating): no-loss / conflict-copy-accounting / wrong-winner need faithful
/// per-op version-vector and concurrency modeling, and the structural
/// index-vs-disk checks are sensitive to the deferred structural-op (rename /
/// move / mkdir / rmdir / chmod) reconciliation fidelity — a structural op is
/// applied straight to disk by `op_applier` but not delivered into the
/// watcher→debounce→index pipeline, so an expected disk/index skew remains that
/// triage's timing knobs cannot distinguish from a real deterministic bug.
fn is_gating(kind: ViolationKind) -> bool {
    matches!(kind, ViolationKind::Convergence | ViolationKind::Corruption)
}

/// Append `case` (with its verdicts and optional minimal repro) to the replay
/// corpus, deduped on seed so repeated runs don't grow the file unboundedly.
fn record_to_corpus(case: &Case, verdicts: Vec<TriageVerdict>, case_min: Option<Case>) {
    let path = corpus_path();
    if corpus::load_corpus(&path).iter().any(|e| e.case.seed == case.seed) {
        return;
    }
    if case_min.is_some() {
        let mut entry = corpus::CorpusEntry::new(case.clone());
        entry.verdicts = verdicts;
        entry.case_min = case_min;
        let _ = corpus::append_entry(&path, &entry);
    } else {
        // The task-named helper for the common (no-shrink) path.
        corpus::record_triaged_case(&path, case, &verdicts);
    }
}

/// Runs one already-generated `Case` through the full failure pipeline:
/// drive -> oracle -> partition gating/advisory -> (on a gating violation)
/// triage -> shrink product bugs -> record the triaged case to the corpus.
fn process_case(case: &Case) -> SeedResult {
    let mut result = SeedResult {
        seed: case.seed,
        product_bugs: Vec::new(),
        artifacts: 0,
        advisory: 0,
        skip: None,
    };

    let violations = match run_case_catching(case, &STANDARD) {
        RunOutcome::Skip(kind) => {
            result.skip = Some(kind);
            return result;
        }
        RunOutcome::Violations(v) => v,
    };
    if violations.is_empty() {
        return result;
    }

    let (gating, advisory): (Vec<Violation>, Vec<Violation>) =
        violations.into_iter().partition(|v| is_gating(v.kind));
    result.advisory = advisory.len();

    if gating.is_empty() {
        // Advisory-only failure: surfaced + counted, but not written to the
        // replay corpus (the corpus is for gating regressions, and advisory
        // findings are the deferred version-vector/structural-fidelity class —
        // recording them would let nondeterministic replay timing flip one
        // into a gating failure and destabilize later runs).
        return result;
    }

    // Triage the gating violations (the genuine product-bug candidates).
    let triaged = corpus::triage_failures(&gating, case, &mut replay);
    let verdicts: Vec<TriageVerdict> = triaged.iter().map(|t| t.verdict).collect();

    let mut case_min: Option<Case> = None;
    for t in &triaged {
        match t.verdict {
            TriageVerdict::LikelyProductBug => {
                let target_kind = t.violation.kind;
                let target_path = t.violation.path.clone();
                let mut reproduce = |candidate: &Case| -> ReproOutcome {
                    match run_case_catching(candidate, &STANDARD) {
                        RunOutcome::Violations(v) => {
                            if v.iter().any(|x| x.kind == target_kind && x.path == target_path) {
                                ReproOutcome::Reproduced
                            } else {
                                ReproOutcome::NotReproduced
                            }
                        }
                        RunOutcome::Skip(_) => ReproOutcome::NotReproduced,
                    }
                };
                let shrunk = shrinker::shrink(
                    case.clone(),
                    &mut reproduce,
                    ShrinkConfig { budget: SHRINK_BUDGET },
                );
                case_min = Some(shrunk.case_min);
                result.product_bugs.push(t.violation.clone());
            }
            TriageVerdict::LikelyHarnessArtifact { .. } => result.artifacts += 1,
        }
    }

    record_to_corpus(case, verdicts, case_min);
    result
}

#[test]
fn dst_generated_sweep() {
    let variations: u64 = std::env::var("DST_VARIATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_VARIATIONS);
    let base_seed: u64 = std::env::var("DST_BASE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_BASE_SEED);

    // Silence the default panic hook for the sweep — `run_case_catching`
    // classifies the caught infra panics itself, so the default hook would
    // just be noise across the batch.
    let previous_hook = std::panic::take_hook();
    let suppress_hook = std::env::var("SWEEP_KEEP_HOOK").is_err();
    if suppress_hook {
        std::panic::set_hook(Box::new(|_| {}));
    }

    let mut coverage = CoverageAccumulator::new();
    let mut seeds_run = 0u64;
    let mut clean = 0u64;
    let mut skipped: HashMap<&'static str, u64> = HashMap::new();
    let mut total_artifacts = 0usize;
    let mut total_advisory = 0usize;
    let mut product_bug_report: Vec<String> = Vec::new();

    // Replay the recorded corpus first: a previously-found failure must always
    // be re-checked, not only surface on whichever sweep found it. Skipped when
    // a run is explicitly targeted (DST_BASE_SEED), the reproduction recipe.
    let targeted = std::env::var("DST_BASE_SEED").is_ok();
    if !targeted {
        for entry in corpus::load_corpus(&corpus_path()) {
            let r = process_case(&entry.case);
            if let Some(kind) = r.skip {
                *skipped.entry(kind).or_default() += 1;
                continue;
            }
            total_artifacts += r.artifacts;
            total_advisory += r.advisory;
            for v in &r.product_bugs {
                product_bug_report.push(format!("[corpus replay] seed {}: {v}", r.seed));
            }
        }
    }

    for i in 0..variations {
        let seed = base_seed.wrapping_add(i);
        let case = generator::generate_case(seed);

        // Sanity guard: the generator must produce a well-formed Case.
        let invalid = generator::validate_case(&case);
        assert!(
            invalid.is_empty(),
            "generator produced an invalid case for seed {seed}: {invalid:?}"
        );

        coverage.record_case(&case);
        seeds_run += 1;

        let r = process_case(&case);
        if let Some(kind) = r.skip {
            *skipped.entry(kind).or_default() += 1;
            continue;
        }
        total_artifacts += r.artifacts;
        total_advisory += r.advisory;
        if r.product_bugs.is_empty() && r.artifacts == 0 && r.advisory == 0 {
            clean += 1;
        }
        for v in &r.product_bugs {
            product_bug_report.push(format!("seed {seed}: {v}"));
        }
    }

    if suppress_hook {
        std::panic::set_hook(previous_hook);
    }

    // Coverage summary + emit.
    let report = coverage.into_report("generated-sweep");
    let emitted = coverage::emit(&coverage::coverage_dir(), &report).ok();

    let total_skipped: u64 = skipped.values().sum();
    println!("\n=== dst_generated_sweep summary ===");
    println!("seeds run: {seeds_run} (clean: {clean}, skipped: {total_skipped} {:?})", skipped);
    println!(
        "violations: {} product-bug (gating), {} harness-artifact (gating oracles), \
         {} advisory (version-vector-model-dependent oracles, non-gating this cut)",
        product_bug_report.len(),
        total_artifacts,
        total_advisory,
    );
    println!(
        "coverage: {} cases, op_kinds {}/{}, fault_kinds {}, topologies {}, \
         op×fault pairs exercised {}, never-exercised {}",
        report.case_count,
        report.op_kinds.len(),
        coverage::OP_KINDS.len(),
        report.fault_kinds.len(),
        report.topologies.len(),
        report.op_fault_pairs.len(),
        report.never_exercised.len(),
    );
    if let Some(p) = emitted {
        println!("coverage report emitted: {}", p.display());
    }
    println!("===================================\n");

    assert!(
        product_bug_report.is_empty(),
        "{} generated seed(s) surfaced a LikelyProductBug oracle violation (harness artifacts \
         are recorded but do not fail the sweep):\n{}\n(reproduce one with \
         DST_BASE_SEED=<seed> DST_VARIATIONS=1)",
        product_bug_report.len(),
        product_bug_report.join("\n---\n"),
    );
    assert!(
        total_skipped < variations.max(1),
        "every seed hit an infra skip — nothing was actually exercised"
    );
}
