//! Broad randomized two-device DST fuzzer: unlike `dst_peer_reconcile_race.rs`,
//! which reproduces one specific, hand-crafted historical race, this scenario
//! drives many randomized rounds of local writes/deletes on *both* real,
//! simulated devices — solo (uncontested) and racing (concurrent,
//! undispatched-vs-incoming) — over a small pool of shared paths, looking
//! for *new*, not-yet-known instances of the same bug class this suite
//! targets: "a durably observed local write is never silently discarded
//! except by a causally-later write/delete." Any violation this scenario
//! finds is filed and fixed as its own
//! follow-up change, not folded into this one.
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
//! propagation between rounds), making a legitimate causally-superseded
//! outcome indistinguishable from real data loss.

#![cfg(madsim)]

mod dst_dag_migrate_b2;
mod dst_support;

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use dst_support::case_ir::{
    Case, ContentTable, DeviceTimeline, FaultPlan, LinkTopology, Op, Topology,
};
use dst_support::clock::HarnessClock;
use dst_support::oracle::GlobalOracle;
use dst_support::reference_model::{self, RefKind, RefOp};
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

/// Sweep-wide reference-model coverage, tallied across every seed this
/// process runs and reported unconditionally by `two_device_chaos_scenario`.
///
/// The reference model abstains *per path*: a raced path's winner is decided
/// by the DAG's `(lamport, change_hash)`, which the input timeline does not
/// determine (see `raced_paths`). With three candidate paths and a 40% race
/// roll per round, whole runs where every touched path raced are common --
/// measured over the 32 default seeds, 9 of them (28%) predict *nothing*.
/// On those seeds `check_reference_model` iterates an empty prediction,
/// asserts nothing, and the seed reports success: an oracle that abstains
/// silently is read as assurance while proving nothing, which is strictly
/// worse than no oracle at all.
///
/// These counters make the abstention impossible to miss -- the sweep prints
/// them on every run, pass or fail, and fails outright if the model predicted
/// nothing across the whole sweep. Same reasoning (and same shape) as the
/// `skipped < variations` guard in `two_device_chaos_scenario`: the number
/// that proves a run exercised something must be visible even when the run
/// is green, or a regression to zero coverage is invisible.
static REFMODEL_SEEDS_PREDICTED: AtomicU64 = AtomicU64::new(0);
static REFMODEL_SEEDS_ABSTAINED_EMPTY: AtomicU64 = AtomicU64::new(0);
/// Seeds whose reference-model check never ran because the mesh was not
/// quiescent -- counted separately so "the model had nothing to say" is never
/// confused with "the model was never asked" (`check_convergence` fails those
/// runs for the real reason).
static REFMODEL_SEEDS_NOT_CONVERGED: AtomicU64 = AtomicU64::new(0);
static REFMODEL_OPS_PREDICTED: AtomicU64 = AtomicU64::new(0);
static REFMODEL_OPS_ABSTAINED: AtomicU64 = AtomicU64::new(0);

/// Smallest sweep the zero-coverage guard is applied to. A fully-raced seed
/// abstains legitimately (measured: 9 of the 32 default seeds), so the guard
/// only means something once enough seeds have run for that draw to average
/// out. At the measured ~28% per-seed abstention rate, eight independent
/// seeds all abstaining is a ~1-in-26,000 event -- rare enough to accuse, and
/// far below the default 32.
const REFMODEL_GUARD_MIN_VARIATIONS: u64 = 8;
const BASELINE_TIMEOUT_MARKER: &str = "BASELINE_TIMEOUT: ";

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
/// progression against a real recovery delay this scenario reliably
/// reproduces: a `BlockRequest` datagram lost at the transport layer
/// during conflict resolution recovers only via `DEFAULT_HYDRATION_
/// TIMEOUT` (30s) plus `reconcile_one_file`'s own bounded retry -- this
/// recovery path was originally misattributed (corrected 2026-07-09) to a
/// self-echo watcher
/// re-observation, which dynamic tracing plus an independent static read
/// ruled out -- this DST harness's simulated watcher cannot re-observe
/// `materialize`'s own writes at all). Production has no "N seconds or
/// fail" gate at all -- only eventual consistency -- so this bound only
/// needs to be "comfortably above the slowest legitimate settle path this
/// scenario can hit", not tight. Loosening it does *not* hide the delay's
/// real cost: the caller records the elapsed time into `GlobalOracle::
/// check_convergence_promptness`, which flags (without blocking round
/// progression) any convergence slower than a realistic SLA.
// This is now the *budget*
// `converge_path` hands to the shared `settle_until` primitive, not a
// hand-rolled poll gate -- the 45s rationale above still governs the value.
const ROUND_SETTLE_BUDGET: Duration = Duration::from_secs(45);

/// The "realistic SLA" `check_convergence_promptness` flags against --
/// comfortably above `ROUND_SETTLE`/`RACE_SETTLE`'s own settle windows
/// plus round-trip margin, well below the lost-block-fetch/hydration-
/// timeout recovery cycle above, so a normal round's ordinary settle
/// never flags while that recovery delay reliably does.
const CONVERGENCE_PROMPTNESS_SLA: Duration = Duration::from_secs(3);

/// Waits until both devices' on-disk bytes at `path` agree -- both absent,
/// or both present and byte-identical -- i.e. a genuinely converged, common
/// base for this path on both sides.
///
/// Gated on *content*, not version-vector equality. A record the DAG
/// materializes carries an empty `VersionVector` (`file_record_from_version`
/// constructs one with `VersionVector::new()`, since the DAG's causality lives
/// in the change ancestry, not in a vector on the record), while the device
/// that made the edit locally still holds the vector its own
/// `LocalChangeProcessor` incremented. Those two never compare `Equal` for a
/// propagated path no matter how long this waits, so a vector-equality gate
/// would be unsatisfiable here. The on-disk bytes are what "the same file on
/// both devices" actually means, and they are what every terminal oracle in
/// this scenario already compares.
///
/// This is what makes a `Race` round's "both sides' edits are genuinely
/// concurrent, so both must survive" assumption actually true: two edits
/// made from a *converged* common base are provably concurrent (neither
/// can have observed the other), exactly `dst_peer_reconcile_race.rs`'s
/// one-time baseline-adoption wait, just repeated before every round
/// here since this scenario reuses a small path pool across many rounds.
/// Without this, a round can legitimately race from two *already-diverged*
/// bases (a prior round's propagation hadn't finished settling), making a
/// genuine, correct causally-superseded outcome indistinguishable from the
/// bug this whole harness exists to catch -- confirmed the hard way (see
/// this file's git history) by chasing what first looked like a real
/// finding back to exactly this gap.
async fn converge_path(
    device_a: &ChaosDevice,
    device_b: &ChaosDevice,
    path: &str,
) -> (bool, Duration) {
    let outcome = dst_support::settle::settle_until(ROUND_SETTLE_BUDGET, || {
        let a = std::fs::read(device_a.root.join(path)).ok();
        let b = std::fs::read(device_b.root.join(path)).ok();
        a == b
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
    // and shorten the heads-announce cadence so DAG catch-up re-drives promptly.
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
        .join("tests/dst_corpus/two_device_chaos_cases.jsonl")
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
///
/// Dedups on `seed` before appending: `two_device_chaos_scenario`'s corpus
/// replay loop below drives entirely off `case.seed` (re-running `run_
/// scenario(seed, ops_per_run)` from scratch, not the recorded `workload`),
/// so a seed already present in the corpus reproduces a byte-for-byte
/// equivalent run every time -- appending it again would only grow the
/// checked-in file with a duplicate line, and every later run pays to
/// replay that same seed twice over. Without this, a flaky/buggy sweep
/// that fails the same seed repeatedly bloats the corpus unboundedly.
fn record_failing_case(case: &Case) {
    let path = corpus_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if load_corpus_cases().iter().any(|existing| existing.seed == case.seed) {
        return;
    }
    let Ok(json) = serde_json::to_string(case) else { return };
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{json}");
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
    dst_support::link::link_and_start(&state_a, &root_a, GROUP_ID)?;

    let root_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_b = root_dir_b.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_b = Arc::new(FsBlockStore::new(store_dir_b.path()).map_err(|e| e.to_string())?);
    let state_b = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    dst_support::link::link_and_start(&state_b, &root_b, GROUP_ID)?;

    let device_a = setup_device("device-a", root_a.clone(), state_a.clone(), store_a.clone());
    let device_b = setup_device("device-b", root_b.clone(), state_b.clone(), store_b.clone());
    // PF (fidelity/artifact-reduction) F.2, agmsg investigation 2026-07-09:
    // held past `connect_sessions` moving its own clones, for the recovery
    // sweep at this scenario's quiescence point (see that call site).
    let recovery_store_a = store_a.clone();
    let recovery_store_b = store_b.clone();
    connect_sessions(&mut rng, &device_a, state_a, store_a, &device_b, state_b, store_b).await;

    // Startup gate: prove the connection is actually up (handshake +
    // first send_index_update round trip) before the randomized rounds
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
    // The independent reference model's input timeline, recorded in lockstep
    // with `recorded_ops`/the oracle but carrying the two things the winner
    // prediction needs and the oracle history does not -- each op's input mtime
    // and its causal round. Built from op *structure* + input mtimes only,
    // never from the implementation's observed version vectors, so the
    // reference winner is derived independently of the code it checks.
    let mut reference_ops: Vec<RefOp> = Vec::new();
    // Paths this run raced on (a round that dispatched two genuinely concurrent
    // edits). The reference model predicts a concurrent write-vs-write winner
    // by last-writer-wins on mtime, which is the *legacy* wire engine's rule.
    // The change-history DAG resolves the same race by `(lamport, change_hash)`
    // (`conflict::dag_conflict_loser_is_a`): both racers derive from the same
    // base, so their lamports tie and the canonical change hash breaks it. That
    // hash is a hash of the signed, canonically-encoded change -- deterministic
    // and identical on every replica, but not derivable from the input timeline
    // without reimplementing the change encoding here, which is exactly the
    // implementation-copying the model exists to avoid. So the model is not
    // wrong-but-fixable on these paths; it has no predictive basis for them at
    // all, and this driver drops them from the timeline before predicting --
    // the same per-path abstention the model already applies to write-vs-delete
    // races, for the same reason (no single winner the inputs determine).
    // Data preservation on raced paths is still fully asserted by
    // `check_no_loss` / `check_convergence` / `check_conflict_copy_accounting`;
    // only the specific-winner claim is dropped, and solo (causally-ordered)
    // paths keep their full wrong-winner coverage, where a later write
    // supersedes an earlier one by ancestry and the model's prediction and the
    // DAG's rule agree.
    //
    // The abstention is per *path*, permanently -- deliberately, and not the
    // narrower per-`(path, round)` drop it looks like it could be. A race
    // leaves a conflict copy, and a conflict copy is a separate file that no
    // later round to the base path ever removes, so it survives into the
    // converged state that gets compared. Abstaining only on the raced round
    // hides the race from the model while leaving its copy on disk: the model
    // then predicts zero conflict copies for a path that really has one, and
    // `check_reference_model` compares that multiset exactly. Measured, not
    // assumed -- narrowing to `(path, round)` raises coverage from 72 to 168
    // predicted ops and then fails 29 of the 32 default seeds, almost all of
    // them "conflict-copy set mismatch: reference model predicts 0 conflict
    // copy/copies, converged disk has 1". False alarms on 29 of 32 seeds are
    // not coverage; they are pressure to delete the oracle. This is the same
    // conclusion, for the same reason, that the model itself reaches for
    // write-vs-delete races (`reference_model`'s
    // `a_single_write_delete_race_abstains_the_whole_path_even_across_later_rounds`:
    // once a path races, its conflict-copy set is permanently unpredictable
    // "even though later rounds are themselves deterministic").
    //
    // The cost is real and is not hidden: 9 of the 32 default seeds race every
    // path they touch and so predict nothing at all. That is what the
    // `REFMODEL_*` counters and the sweep's unconditional summary exist to
    // report -- see their doc comments.
    let mut raced_paths: std::collections::HashSet<&'static str> = std::collections::HashSet::new();
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
        let kind_roll = rng.random_range(0..10);
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
            // a convergence
            // timeout is now a genuine scenario FAILURE, not a skip --
            // oracle #1 requirement ("a convergence timeout
            // is a FAILURE, not a skip -- today dst skips it, and that
            // hides data loss"). Deliberately still returned as a plain
            // `Err` (no marker prefix): `BASELINE_TIMEOUT_MARKER` above
            // and `TIME_LIMIT_MARKER`/`RESOURCE_EXHAUSTION_MARKER` below
            // stay classified as skips (genuine simulated-runtime/session-
            // establishment infra issues, not this scenario's own
            // sync-correctness assertion), but `CONVERGENCE_TIMEOUT_MARKER`
            // itself is retired -- see `two_device_chaos_scenario`'s
            // sweep-aggregation loop, which no longer recognizes it as a
            // skip category.
            return Err(format!(
                "seed {seed}: round {round}, path {path} never converged across both devices \
                 within the poll timeout -- treated as a failure (not skipped): either a genuine \
                 propagation bug, or the poll timeout is too tight for this host's current load"
            ));
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
                reference_ops.push(RefOp {
                    path: path.to_string(),
                    device_id: device.device_id.clone(),
                    round: round as u64,
                    kind: RefKind::Write { content_id },
                    mtime_nanos: clock.now_nanos(),
                });
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
                    reference_ops.push(RefOp {
                        path: path.to_string(),
                        device_id: device.device_id.clone(),
                        round: round as u64,
                        kind: RefKind::Delete,
                        mtime_nanos: clock.now_nanos(),
                    });
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
                    reference_ops.push(RefOp {
                        path: path.to_string(),
                        device_id: device.device_id.clone(),
                        round: round as u64,
                        kind: RefKind::Write { content_id },
                        mtime_nanos: clock.now_nanos(),
                    });
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
                // This path's converged winner is now decided by the DAG's
                // (lamport, change_hash), which the reference model cannot
                // derive from the input timeline -- abstain on it (see
                // `raced_paths`).
                raced_paths.insert(path);
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
                // `x`'s mtime is the round's pre-`y` value; `y` below stamps
                // a strictly-later mtime (the +100ms bump), so `y` is the
                // newer, canonical-name-winning side by LWW.
                reference_ops.push(RefOp {
                    path: path.to_string(),
                    device_id: x.device_id.clone(),
                    round: round as u64,
                    kind: RefKind::Write { content_id: x_content_id },
                    mtime_nanos: clock.now_nanos(),
                });

                deliver_local_write(x, path, x_content.clone(), &clock).await?;
                tokio::time::sleep(RACE_INNER_DELAY).await;

                // `y` happens strictly after `x` within this same round: the
                // relative ordering that decides the conflict is the version
                // vector (`y_version` below), and y's own `fs_ops::write`
                // advances the shared clock again so its stamped mtime lands
                // strictly after x's -- no hand-tuned +100ms sub-step needed
                // (the per-mutation stamp gives the ordering for free).

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
                    reference_ops.push(RefOp {
                        path: path.to_string(),
                        device_id: y.device_id.clone(),
                        round: round as u64,
                        kind: RefKind::Delete,
                        mtime_nanos: clock.now_nanos(),
                    });
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
                    reference_ops.push(RefOp {
                        path: path.to_string(),
                        device_id: y.device_id.clone(),
                        round: round as u64,
                        kind: RefKind::Write { content_id: y_content_id },
                        mtime_nanos: clock.now_nanos(),
                    });
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
    // false signal this scenario's own `converge_path` was written to close
    // for the *per-round* gate (see its doc comment's "confirmed the hard way"
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
    const FINAL_CONVERGENCE_BUDGET: Duration = Duration::from_secs(60);
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
    // merely slow.
    let convergence_violations = oracle.check_convergence(&devices);
    // Whether the mesh is genuinely quiescent right now -- the reference-model
    // check below is only well-posed at a converged point.
    let is_converged_now = converged && convergence_violations.is_empty();
    violations.extend(convergence_violations);
    violations.extend(oracle.check_no_loss(&content_table, &devices));
    violations.extend(oracle.check_conflict_copy_accounting(&content_table, &devices, GROUP_ID));
    violations.extend(oracle.check_no_corruption(&content_table, &devices, GROUP_ID));
    violations.extend(oracle.check_structural(GROUP_ID, &devices));
    // The independent reference-model check -- catches a consistent-but-wrong
    // converged winner the five checks above are all structurally blind to.
    // Re-derives the expected live winner + conflict-copy multiset per path
    // from the input timeline (`reference_ops`), never from the version vectors
    // the implementation produced, then compares to the real converged disk
    // state. `i64::MAX` for `now`: this scenario's mtimes are always <= the
    // current virtual clock, so the future-skew clamp is a no-op here (only
    // adversarial mtimes engage it, which this scenario never generates).
    //
    // Raced paths are dropped from the timeline first: their winner is decided
    // by the DAG's (lamport, change_hash), which the model has no independent
    // way to predict (see `raced_paths`). Solo, causally-ordered paths keep the
    // full check -- there the model's "the latest write is live, with no
    // conflict copy" prediction is exactly what DAG ancestry supersession
    // produces.
    //
    // Gated on genuine convergence: "which content is the canonical winner"
    // is only well-posed at a quiescent, converged point. If the devices
    // have not converged, `check_convergence` already fails the run for the
    // real reason -- reading a mid-flight, still-diverged disk state here
    // would only pile a redundant wrong-winner signal on top of it (observed
    // in a 300-seed sweep: the *only* reference-model finding was exactly
    // such a non-converged batch-runtime-isolation artifact, co-reported
    // with a Convergence failure).
    if is_converged_now {
        let total_ops = reference_ops.len();
        reference_ops.retain(|op| !raced_paths.contains(op.path.as_str()));
        let predicted_ops = reference_ops.len();
        let prediction = reference_model::predict(&reference_ops, i64::MAX);
        // Unconditional (not `debug`-gated) -- the whole point of the counters
        // above. An abstaining oracle must say so on the run where it
        // abstained, not only in an aggregate someone has to go looking for.
        let mut predicted_paths: Vec<&str> = prediction.paths.keys().map(|p| p.as_str()).collect();
        predicted_paths.sort_unstable();
        eprintln!(
            "  REFMODEL: seed {seed}: predicted {} path(s) {predicted_paths:?} from \
             {predicted_ops}/{total_ops} ops; abstained on {} raced path(s) ({} ops)",
            prediction.paths.len(),
            raced_paths.len(),
            total_ops - predicted_ops,
        );
        REFMODEL_OPS_PREDICTED.fetch_add(predicted_ops as u64, Ordering::Relaxed);
        REFMODEL_OPS_ABSTAINED.fetch_add((total_ops - predicted_ops) as u64, Ordering::Relaxed);
        if prediction.paths.is_empty() {
            REFMODEL_SEEDS_ABSTAINED_EMPTY.fetch_add(1, Ordering::Relaxed);
        } else {
            REFMODEL_SEEDS_PREDICTED.fetch_add(1, Ordering::Relaxed);
        }
        violations.extend(reference_model::check_reference_model(
            &prediction,
            &content_table,
            &devices,
        ));
    } else {
        REFMODEL_SEEDS_NOT_CONVERGED.fetch_add(1, Ordering::Relaxed);
    }

    // PF promptness oracle, agmsg investigation 2026-07-09: deliberately
    // *not* folded into `violations` above -- these never gate this run's
    // pass/fail (`ROUND_SETTLE_BUDGET` above already tolerates the
    // lost-block-fetch/hydration-timeout recovery cycle; failing the run
    // again here would just re-hide the same cost behind a different
    // violation kind). Always printed (not just under `debug`): this is
    // exactly the "measure it, show it, don't hide it" signal
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
            fault_schedule: Vec::new(),
            content_table,
            fault_plan: FaultPlan::default(),
        };
        record_failing_case(&case);
        return Err(dst_support::oracle::format_violations(seed, &violations));
    }
    Ok(())
}

fn run_in_madsim(seed: u64, ops_per_run: usize) -> Result<(), String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    // Comfortable margin above `FINAL_CONVERGENCE_BUDGET` (60s) plus the
    // rounds' own settle time -- was raised from the original 60s while
    // investigating a real convergence-latency bug (see that constant's
    // own doc comment); kept above 60s permanently since a genuine,
    // production-legitimate ~30s hydration-timeout retry can now push a
    // run past the old bound without this being a scenario bug.
    rt.set_time_limit(Duration::from_secs(100));
    rt.block_on(run_scenario(seed, ops_per_run)).map_err(|e| {
        // Uniformly tag every failure with its seed for reproduction,
        // without double-tagging the ones (`BASELINE_TIMEOUT_MARKER`, the
        // convergence-timeout error, the oracle violation report) that
        // already include it, and without burying `BASELINE_TIMEOUT_
        // MARKER`'s recognizable prefix under a "seed N: " prefix.
        if e.starts_with(BASELINE_TIMEOUT_MARKER) || e.contains(&format!("seed {seed}")) {
            e
        } else {
            format!("seed {seed}: {e}")
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
/// True when the caller has explicitly targeted this run via
/// `DST_BASE_SEED`/`DST_VARIATIONS` -- see `two_device_chaos_scenario`'s
/// corpus-replay-loop doc comment for why a targeted run skips replaying
/// the corpus.
fn is_targeted_corpus_replay_skip() -> bool {
    std::env::var("DST_BASE_SEED").is_ok() || std::env::var("DST_VARIATIONS").is_ok()
}

#[test]
fn two_device_chaos_scenario() {
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
    //
    // Skipped when the caller has explicitly targeted this run via
    // `DST_BASE_SEED`/`DST_VARIATIONS` (the exact reproduction recipe this
    // test's own failure message documents: "DST_BASE_SEED=<seed>
    // DST_VARIATIONS=1"). Without this gate, a corpus that has accumulated
    // real regression cases over time gets replayed in full underneath
    // *every* run regardless of what was asked for -- a developer
    // reproducing one specific seed pays the wall-clock/resource cost of
    // (and can have their targeted result muddied by an unrelated failure
    // from) the entire corpus, and the corpus replay's own cumulative
    // resource use (fresh `SyncState`s, threads -- see `RESOURCE_
    // EXHAUSTION_MARKER`) eats into the budget the targeted seeds were
    // meant to have. A plain default-argument run (as CI performs) still
    // replays the full corpus, preserving the regression-corpus intent.
    if !is_targeted_corpus_replay_skip() {
        for case in load_corpus_cases() {
            match run_seed_catching_time_limit(case.seed, ops_per_run) {
                Ok(()) => {}
                Err(e) if e.starts_with(BASELINE_TIMEOUT_MARKER) => skipped_baseline += 1,
                Err(e) if e.starts_with(TIME_LIMIT_MARKER) => skipped_time_limit += 1,
                Err(e) if e.starts_with(RESOURCE_EXHAUSTION_MARKER) => {
                    skipped_resource_exhaustion += 1
                }
                Err(e) => failures.push(format!("[corpus replay] {e}")),
            }
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

    // Reference-model coverage, printed before the pass/fail asserts so it
    // lands on every run -- green ones included. `cargo test` swallows this
    // unless the run fails or `--nocapture` is passed, which is precisely why
    // the vacuity guard below is an `assert!` and not just a line of output:
    // the number has to be able to fail the build on its own.
    let seeds_predicted = REFMODEL_SEEDS_PREDICTED.load(Ordering::Relaxed);
    let seeds_abstained_empty = REFMODEL_SEEDS_ABSTAINED_EMPTY.load(Ordering::Relaxed);
    let seeds_not_converged = REFMODEL_SEEDS_NOT_CONVERGED.load(Ordering::Relaxed);
    let ops_predicted = REFMODEL_OPS_PREDICTED.load(Ordering::Relaxed);
    let ops_abstained = REFMODEL_OPS_ABSTAINED.load(Ordering::Relaxed);
    let refmodel_summary = format!(
        "reference model: {seeds_predicted} seed(s) predicted a winner, \
         {seeds_abstained_empty} abstained entirely (every touched path raced), \
         {seeds_not_converged} never reached a quiescent point to check; \
         {ops_predicted} op(s) predicted / {ops_abstained} abstained"
    );
    eprintln!("{refmodel_summary}");

    let skipped = skipped_baseline + skipped_time_limit + skipped_resource_exhaustion;
    assert!(
        failures.is_empty(),
        "{}/{variations} chaos variations found an oracle violation (skipped {skipped_baseline} \
         on baseline timeout, {skipped_time_limit} on the madsim time limit, \
         {skipped_resource_exhaustion} on OS thread-creation exhaustion -- see \
         RESOURCE_EXHAUSTION_MARKER's doc comment if this count is high; a round-convergence \
         timeout is no longer skipped -- it appears among the failures below):\n{}\n\
         (reproduce one with DST_BASE_SEED=<seed> DST_VARIATIONS=1 cargo test ... \
         two_device_chaos_scenario, then narrow to run_scenario(seed, ops) directly)",
        failures.len(),
        failures.join("\n---\n")
    );
    assert!(
        skipped < variations,
        "every seed hit BASELINE_TIMEOUT -- nothing was actually exercised"
    );
    // The reference model's own vacuity guard. It legitimately abstains on
    // raced paths, so a *single* empty seed proves nothing is wrong -- but a
    // sweep in which it never once predicted a winner means the wrong-winner
    // oracle contributed no coverage at all, and every one of those green
    // seeds was green for free. That is the failure this whole check exists
    // to prevent, so it fails the run rather than printing into a void.
    // Deliberately `> 0` and not a ratio: the per-seed outcome is a random
    // draw, and a threshold tight enough to catch a small regression would
    // also fire on an unlucky-but-honest sweep. The unconditional summary
    // above carries the actual ratio for anyone reading it; this guard
    // catches only the floor.
    //
    // Gated on sweep size: a single fully-raced seed abstains *legitimately*,
    // so applying this to a targeted `DST_VARIATIONS=1` reproduction -- the
    // exact recipe the failure message above tells people to run -- would
    // turn a valid debugging run into a spurious failure. The guard is a
    // claim about a sweep's aggregate coverage, and only a sweep can answer
    // it.
    if variations >= REFMODEL_GUARD_MIN_VARIATIONS {
        assert!(
            seeds_predicted > 0,
            "{refmodel_summary}\nthe reference model never predicted a winner on any seed this \
             run (>= {REFMODEL_GUARD_MIN_VARIATIONS} variations, plus any corpus replay) -- the \
             wrong-winner oracle added ZERO coverage, so its silence cannot be read as a pass \
             (check whether `raced_paths` is over-abstaining)"
        );
    }
}
