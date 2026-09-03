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
//! propagation between rounds), making a legitimate `ChangeOrdering::Before`
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

use dst_support::case_ir::{
    Case, ContentTable, DeviceTimeline, Fault, FaultPlan, LinkTopology, NetFault, Op, Topology,
};
use dst_support::clock::HarnessClock;
use dst_support::oracle::GlobalOracle;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::debounce::{self, DebounceConfig, FlushPathRequest};
use yadorilink_filesystem_sync::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource,
};
use yadorilink_local_capture::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_peer_session::peer_session::{
    PeerSyncSession, PendingLocalChangeFlush, PendingLocalFlushOutcome,
};

/// The most recent change `device` authored touching `path` — the causal
/// evidence the oracle compares by DAG ancestry.
///
/// Forces the device's pending local change for this path through the
/// debounce accumulator and the processor first, rather than sleeping and
/// hoping. `flush_pending_local_change` is the production-wired settle
/// primitive: it awaits `process_flush`, which appends the signed change, so
/// on return the history is authoritative for this path.
///
/// Two weaker versions of this were tried and measured. A fixed settle window
/// was flaky (the local flush->author chain is not fully virtualized under
/// madsim: real tempdir I/O on a real threadpool). Polling until the hash
/// merely became non-`None` was worse and silently wrong: for the second and
/// later op the same device performs on the same path, a stale answer is
/// already present, so it returned instantly with the *previous* change's
/// hash. On seed 3298840576 that made three consecutive device-a ops on
/// `chaos-b.bin` all report `e2e5e013`, so the delete failed to supersede the
/// write it actually superseded (`supersedes()` is `false` on equal hashes)
/// and a phantom pair of `NoLoss` violations appeared. Polling until the hash
/// *changed* fixed that but was too strong in the other direction — an op
/// that legitimately authors nothing (a content-identical rewrite) never
/// advances the hash, which broke corpus replay.
async fn authoring_of(
    device: &ChaosDevice,
    path: &str,
) -> Option<yadorilink_replica_domain::ids::ChangeHash> {
    device.flush_pending_local_change(GROUP_ID, path).await;
    device
        .state
        .change_history_repository()
        .dag_last_authored_change_for_path(GROUP_ID, &device.device_id, path)
        .ok()
        .flatten()
}

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
    state: Arc<ReplicaCoordinator>,
    processor: Arc<LocalChangeProcessor>,
    events_tx: tokio::sync::mpsc::Sender<FsChangeEvent>,
    flush_request_tx: tokio::sync::mpsc::Sender<FlushPathRequest>,
    session: OnceLock<Arc<PeerSyncSession>>,
}

impl ChaosDevice {
    /// Harness twin of
    /// `link_runtime::LinkFlushHandle::capture_undiscovered_local_change`:
    /// when the debounce accumulator reports nothing pending for a path,
    /// check the path on disk directly rather than concluding there is
    /// nothing local to protect. Same `CreatedOrModified`-only,
    /// skip-if-absent discipline as production (see that method's doc
    /// comment for why synthesizing `Removed` here would corrupt the very
    /// comparison the caller is about to make).
    async fn capture_undiscovered_local_change(&self, group_id: &str, path: &Path) {
        if path.symlink_metadata().is_err() {
            return; // nothing on disk at this path -- nothing to protect
        }
        let event =
            FsChangeEvent { path: path.to_path_buf(), kind: FsChangeKind::CreatedOrModified };
        let Ok(outcome) = self.processor.process_event(group_id, &self.root, &event).await else {
            return;
        };
        let changed = match outcome {
            LocalChangeOutcome::FileChanged(_) => true,
            LocalChangeOutcome::FilesChanged(ref records) => !records.is_empty(),
            LocalChangeOutcome::None => false,
        };
        if !changed {
            return;
        }
        if std::env::var("DST_CHAOS_DEBUG").is_ok() {
            eprintln!(
                "  [{}] undiscovered-change fallback captured: path={:?}",
                self.device_id, path
            );
        }
        if let Some(session) = self.session.get() {
            let _ = session.announce_local_commit(group_id).await;
        }
    }
}

impl PendingLocalChangeFlush for ChaosDevice {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
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
                return PendingLocalFlushOutcome::Settled;
            }
            let found = match tokio::time::timeout(Duration::from_millis(500), reply_rx).await {
                Ok(Ok(found)) => found,
                _ => None,
            };
            // Mirrors production's
            // `link_runtime::LinkFlushHandle::flush_pending_local_change`,
            // which does *not* treat a `None` reply as "nothing to protect":
            // it falls back to a direct, disk-authoritative
            // `capture_undiscovered_local_change` for this exact path. This
            // harness used to `return` here instead, which made every
            // scenario built on it test a configuration production never
            // runs -- and made the `None` branch, the one a queued-but-
            // unpolled watcher event lands on, silently lossy. That is the
            // mechanism behind this scenario's `[NoLoss]` violations on
            // seeds 3298840576/3298840578.
            let Some((found_path, kind, observed_at)) = found else {
                self.capture_undiscovered_local_change(group_id, &path).await;
                return PendingLocalFlushOutcome::Settled;
            };
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
            PendingLocalFlushOutcome::Settled
        })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
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
                return PendingLocalFlushOutcome::Settled;
            }
            let found = match tokio::time::timeout(Duration::from_millis(500), reply_rx).await {
                Ok(Ok(found)) => found,
                _ => None,
            };
            let Some((sibling_path, kind, observed_at)) = found else {
                return PendingLocalFlushOutcome::Settled;
            };
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
            PendingLocalFlushOutcome::Settled
        })
    }
}

/// Sets up one device's real watcher-boundary/debounce/`LocalChangeProcessor`
/// pipeline, with the executor forwarding every non-empty flush result to
/// this device's (not-yet-connected) session the same way
/// `link_runtime::operations::capture_local_change::announce_local_change`
/// -> `DaemonState::broadcast_change`
/// does in production for a send-receive link.
fn setup_device(
    device_id: &str,
    root: PathBuf,
    sync_state: Arc<ReplicaCoordinator>,
    store: Arc<FsBlockStore>,
) -> Arc<ChaosDevice> {
    let processor = Arc::new(
        LocalChangeProcessor::new(
            sync_state.clone(),
            store,
            device_id.to_string(),
            Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(dst_dag_migrate_b2::emitter_for(device_id)),
    );
    let (flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    let (watch_source, events_tx) = SimulatedFolderWatchSource::new(32);
    let ignore_set =
        Arc::new(yadorilink_root_authority::ignore_patterns::EffectiveIgnoreSet::defaults_only());
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
/// a genuine, correct `ChangeOrdering::Before` outcome indistinguishable
/// from the bug this whole harness exists to catch -- confirmed the hard
/// way (see this file's git history) by chasing what first looked like a
/// real finding back to exactly this gap.
async fn converge_path(
    device_a: &ChaosDevice,
    device_b: &ChaosDevice,
    path: &str,
) -> (bool, Duration) {
    let outcome = dst_support::settle::settle_until(ROUND_SETTLE_BUDGET, || {
        let a = device_a.state.file_index_repository().get_file(GROUP_ID, path).ok().flatten();
        let b = device_b.state.file_index_repository().get_file(GROUP_ID, path).ok().flatten();
        match (&a, &b) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                // Convergence is identity of the authoring change, not equality
                // of a per-file counter.
                a == b
                    && device_a
                        .state
                        .file_index_repository()
                        .get_authoring_change_hash(GROUP_ID, path)
                        .ok()
                        .flatten()
                        == device_b
                            .state
                            .file_index_repository()
                            .get_authoring_change_hash(GROUP_ID, path)
                            .ok()
                            .flatten()
            }
            _ => false,
        }
    })
    .await;
    (outcome.converged, outcome.elapsed)
}

async fn connect_sessions(
    rng: &mut StdRng,
    device_a: &Arc<ChaosDevice>,
    state_a: Arc<ReplicaCoordinator>,
    store_a: Arc<FsBlockStore>,
    device_b: &Arc<ChaosDevice>,
    state_b: Arc<ReplicaCoordinator>,
    store_b: Arc<FsBlockStore>,
) {
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let (channel_a, channel_b) = quic_channel_pair(socket_a, socket_b).await;

    // On the change-history DAG a conflict copy needs no daemon-style
    // `broadcast_change` re-fan-out: each device materializes the same conflict
    // copy locally from the shared change set (both sides pull every change via
    // the heads-announce -> change-request -> change-batch loop), so the legacy
    // forwarding channel (`new_with_forwarding` + a re-`send_index_update`
    // loop) is dropped. Both devices run the plain session and converge by
    // pulling each other's announced heads.
    // Pin both devices' verifying keys (each admits the other's signed changes)
    // -- moved ahead of session construction since `ChangeAuthenticator`/
    // `PendingLocalChangeFlush` are now construction-only
    // `PeerSyncSessionDeps` fields, not post-hoc setters.
    let device_ids = [device_a.device_id.as_str(), device_b.device_id.as_str()];
    let authenticator = dst_dag_migrate_b2::PinnedAuthenticator::new(device_ids);

    let mut sync_roots_a = HashMap::new();
    sync_roots_a.insert(GROUP_ID.to_string(), device_a.root.clone());
    let session_a = PeerSyncSession::new_with_dependencies(
        channel_a,
        device_a.device_id.clone(),
        device_b.device_id.clone(),
        state_a,
        store_a,
        vec![GROUP_ID.to_string()],
        sync_roots_a,
        None,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps {
            root_commit_authority_provider: std::sync::Arc::new(
                dst_support::link::TestRootCommitAuthorityProvider,
            ),
            pending_local_change_flush: device_a.clone(),
            change_authenticator: authenticator.clone(),
            ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
        },
    );

    let mut sync_roots_b = HashMap::new();
    sync_roots_b.insert(GROUP_ID.to_string(), device_b.root.clone());
    let session_b = PeerSyncSession::new_with_dependencies(
        channel_b,
        device_b.device_id.clone(),
        device_a.device_id.clone(),
        state_b,
        store_b,
        vec![GROUP_ID.to_string()],
        sync_roots_b,
        None,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps {
            root_commit_authority_provider: std::sync::Arc::new(
                dst_support::link::TestRootCommitAuthorityProvider,
            ),
            pending_local_change_flush: device_b.clone(),
            change_authenticator: authenticator,
            ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
        },
    );

    device_a.session.set(session_a.clone()).ok();
    device_b.session.set(session_b.clone()).ok();

    // Shorten the heads-announce cadence so DAG catch-up re-drives promptly
    // under packet loss / a partition window.
    let device_ids = [device_a.device_id.as_str(), device_b.device_id.as_str()];
    let group_ids = [GROUP_ID];
    dst_dag_migrate_b2::wire_dag_session(
        &session_a,
        device_a.state.clone(),
        &device_ids,
        &group_ids,
    );
    dst_dag_migrate_b2::wire_dag_session(
        &session_b,
        device_b.state.clone(),
        &device_ids,
        &group_ids,
    );

    tokio::spawn(session_a.run());
    tokio::spawn(session_b.run());
}

fn device_has_live_record(device: &ChaosDevice, path: &str) -> bool {
    device
        .state
        .file_index_repository()
        .get_file(GROUP_ID, path)
        .ok()
        .flatten()
        .map(|r| !r.deleted)
        .unwrap_or(false)
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
            // heads so the peer pulls it over the DAG. Best-effort, matching
            // every other `announce_local_commit` call site in this file
            // (`ChaosDevice::capture_undiscovered_local_change`,
            // `flush_pending_local_change`, `flush_case_fold_sibling`, all
            // `let _ = ...`) -- `wire_dag_session`'s own doc comment is
            // explicit that this one-shot announce is not the only path a
            // committed edit has to reach the peer: `run()`'s own loop
            // re-announces an idempotent `HeadsAnnounce` on a shortened
            // cadence specifically so a lost announce "rides through packet
            // loss / a partition window" instead of needing to itself
            // succeed. Propagating this as `?` (this call site's own prior
            // behavior) turned an expected, harness-modeled transient --
            // under 27%+ steady loss plus an injected partition, the
            // control-stream send this wraps can legitimately race a
            // still-recovering path -- into a hard scenario failure
            // ("transport error: peer channel closed", corpus seed
            // 3298840588) before the scenario's own convergence oracle ever
            // got a chance to be the authority on whether the write
            // actually failed to land.
            let _ = session.announce_local_commit(GROUP_ID).await;
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
///
/// Its only caller is `run_scenario`, gated there on `record_promotable_
/// failures` -- see that parameter's doc comment on `run_seed_catching_
/// time_limit` for why this must never be unconditional: it mutates a
/// file this repo tracks in git, and only the fresh-sweep loop's
/// discovery of a genuinely new failure is a reason to do that.
fn record_failing_case(case: &Case) {
    record_case_to(case, &corpus_path())
}

/// The actual append, taking `path` explicitly rather than always going
/// through `corpus_path()` -- this is what lets `corpus_write_is_gated`
/// below exercise the real write against a throwaway tempfile instead of
/// the tracked corpus, while `record_failing_case` (the only production
/// caller) still always targets the real path.
fn record_case_to(case: &Case, path: &std::path::Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(json) = serde_json::to_string(case) else { return };
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{json}");
    }
}

/// The gate `run_scenario` applies before calling `record_failing_case` --
/// factored out so `corpus_write_is_gated` below can exercise the exact
/// same decision the real scenario makes, against a throwaway path,
/// without needing a full madsim network run to force a violation.
fn maybe_record_case(case: &Case, record_promotable_failures: bool, path: &std::path::Path) {
    if record_promotable_failures {
        record_case_to(case, path);
    }
}

/// Plain (non-madsim) regression guard for the corpus-write gate: a
/// scenario run must never dirty `tests/dst_corpus/` (a file this repo
/// tracks in git) unless its caller explicitly opted in via
/// `record_promotable_failures`. Recording used to fire unconditionally
/// from inside `run_scenario`, invisible to every caller -- this is what
/// let corpus replay silently re-append an already-known case on every
/// re-failure, and what let an unrelated ad hoc diagnostic
/// (`batch_position_probe`) mutate the tracked corpus with no code at its
/// own call site suggesting it could (see both functions' doc comments).
///
/// Runs directly against `maybe_record_case` -- the exact gate
/// `run_scenario` applies -- rather than a real scenario, so it stays fast
/// and deterministic instead of depending on any seed actually producing a
/// violation.
#[test]
fn corpus_write_is_gated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe_cases.jsonl");
    let case = Case {
        seed: 0,
        topology: Topology { device_count: 2, links: Vec::new() },
        workload: Vec::new(),
        fault_schedule: Vec::new(),
        content_table: Default::default(),
        fault_plan: FaultPlan::default(),
    };

    maybe_record_case(&case, false, &path);
    assert!(!path.exists(), "record_promotable_failures=false must never touch the corpus file");

    maybe_record_case(&case, true, &path);
    assert!(
        path.exists(),
        "record_promotable_failures=true must actually persist -- otherwise this guard could \
         pass by accident (the gate doing nothing at all, rather than gating correctly)"
    );
    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents.lines().count(), 1, "exactly one case recorded, not zero and not many");
}

async fn run_scenario(
    seed: u64,
    ops_per_run: usize,
    fault_profile: FaultProfile,
    record_promotable_failures: bool,
) -> Result<(), String> {
    let _ = tracing_subscriber::fmt::try_init();
    let mut rng = StdRng::seed_from_u64(seed);

    let root_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_a = root_dir_a.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_a = Arc::new(FsBlockStore::new(store_dir_a.path()).map_err(|e| e.to_string())?);
    let state_a = Arc::new(ReplicaCoordinator::open_in_memory().map_err(|e| e.to_string())?);
    dst_support::link::link_and_start(&state_a, &root_a, GROUP_ID).map_err(|e| e.to_string())?;
    let root_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_b = root_dir_b.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_b = Arc::new(FsBlockStore::new(store_dir_b.path()).map_err(|e| e.to_string())?);
    let state_b = Arc::new(ReplicaCoordinator::open_in_memory().map_err(|e| e.to_string())?);
    dst_support::link::link_and_start(&state_b, &root_b, GROUP_ID).map_err(|e| e.to_string())?;
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
             timeout -- a host-load-dependent startup stall, not a bug in this scenario (the old \
             WireGuard-handshake-livelock attribution was disproven; see issue #26)"
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
        if round_converged {
            // Only a genuinely-converged round has a real "how long did
            // convergence take" latency to feed the promptness oracle --
            // a round that hit `ROUND_SETTLE_BUDGET` without converging
            // has an *unmeasured* true convergence time (it could be
            // anywhere beyond the budget), not a measured "took 45s".
            // Recording it here would print as "convergence took
            // 45.000045s" alongside `check_convergence_promptness`'s SLA
            // message, reading as a completed-but-slow convergence when
            // it is actually a still-diverged timeout.
            oracle.record_round_convergence_latency(path, round_convergence_elapsed);
        } else {
            eprintln!(
                "  NETWORK-FAULT: seed {seed} round {round} path {path} did not converge \
                 within the {ROUND_SETTLE_BUDGET:?} round-settle budget; continuing so final \
                 heal/resync oracle decides pass/fail"
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
                oracle.record_write(
                    path,
                    device_idx_of(device),
                    content_id,
                    authoring_of(device, path).await,
                );
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

                    oracle.record_delete(
                        path,
                        device_idx_of(device),
                        authoring_of(device, path).await,
                    );
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
                    oracle.record_write(
                        path,
                        device_idx_of(device),
                        content_id,
                        authoring_of(device, path).await,
                    );
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
                let x_content_id = next_content_id;
                next_content_id += 1;
                content_table.insert(x_content_id, x_content.clone());
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
                // Both sides' oracle entries are recorded together after the
                // whole race has settled, below. Recording is a pure model
                // action, and the causal evidence it needs -- the change each
                // device authored for `path` -- is read from the retained
                // history, not from the current projection, so it survives
                // `x`'s content being renamed away by conflict resolution.
                // (The pre-DAG model had to synthesize `x`'s version vector
                // precisely because there was no such moment.) Reading it any
                // earlier just races the local flush and yields no evidence at
                // all, which fails loud as "never superseded".
                let y_op;
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
                    y_op = Op::Delete { path: path.to_string() };
                } else {
                    let y_content = content_for(seed, round, &y.device_id, "race-y");
                    let y_path = y.root.join(path);
                    dst_support::fs_ops::write(&clock, &y_path, &y_content)?;
                    apply_and_push(y, path, FsChangeKind::CreatedOrModified).await?;
                    let y_content_id = next_content_id;
                    next_content_id += 1;
                    content_table.insert(y_content_id, y_content);
                    y_op = Op::Write { path: path.to_string(), content_id: y_content_id };
                }

                tokio::time::sleep(RACE_SETTLE).await;
                oracle.record_write(
                    path,
                    device_idx_of(x),
                    x_content_id,
                    authoring_of(x, path).await,
                );
                recorded_ops.push((
                    device_idx_of(x),
                    round as u64,
                    Op::Write { path: path.to_string(), content_id: x_content_id },
                ));
                match &y_op {
                    Op::Delete { .. } => {
                        oracle.record_delete(path, device_idx_of(y), authoring_of(y, path).await);
                    }
                    Op::Write { content_id, .. } => {
                        oracle.record_write(
                            path,
                            device_idx_of(y),
                            *content_id,
                            authoring_of(y, path).await,
                        );
                    }
                    other => {
                        unreachable!("y's race op is only ever a write or a delete: {other:?}")
                    }
                }
                recorded_ops.push((device_idx_of(y), round as u64, y_op));
            }
        }
    }

    let devices: Vec<(&Path, &ReplicaCoordinator)> = vec![
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
    // anywhere near `DEFAULT_MAINTENANCE_RECONCILE_INTERVAL`'s (~90s) scale is
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
    // (`link_runtime`) -- this bare-`PeerSyncSession` harness never
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
    violations.extend(oracle.check_no_loss(&content_table, &devices, GROUP_ID));
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
        // Only the caller that genuinely wants to promote a newly
        // discovered failure into the corpus opts in -- see
        // `run_seed_catching_time_limit`'s doc comment on why every other
        // caller (corpus replay itself, and any ad hoc diagnostic) must
        // NOT re-persist a case here. Recording used to be unconditional,
        // fired from inside this function for every caller regardless of
        // intent, which is what let corpus replay silently re-append an
        // already-known case on every re-failure and let an unrelated
        // diagnostic mutate a tracked file with no caller-visible sign it
        // could.
        if record_promotable_failures {
            record_failing_case(&case);
        }
        return Err(format!(
            "{}\nfault_profile: {}",
            dst_support::oracle::format_violations(seed, &violations),
            fault_profile.describe()
        ));
    }
    Ok(())
}

fn run_in_madsim(
    seed: u64,
    ops_per_run: usize,
    record_promotable_failures: bool,
) -> Result<(), String> {
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
    rt.block_on(run_scenario(seed, ops_per_run, fault_profile, record_promotable_failures)).map_err(
        |e| {
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
        },
    )
}

/// Prefix marking a seed as hitting `madsim`'s hard 60-simulated-second
/// time limit -- `Runtime::block_on` panics directly rather than
/// returning an `Err` when this happens, so unlike every other outcome
/// this one is caught via `catch_unwind`, not `?`. Classified the same
/// way as `BASELINE_TIMEOUT_MARKER` (a skip, not a scenario failure):
/// empirically, every occurrence found while scaling this scenario's
/// seed count up traced to the same shape as
/// `dst_peer_reconcile_race.rs`'s `BASELINE_TIMEOUT_MARKER` -- a
/// batch-load-dependent startup stall for a specific seed, not a
/// deadlock in this scenario's own logic (isolating each hanging seed
/// with `DST_VARIATIONS=1` never reproduced it standalone, only as part
/// of a larger sequential batch -- consistent with the
/// network-touching-runtime isolation gap both DST peer-session files
/// already document). The old attribution of these stalls to a
/// WireGuard-handshake livelock was disproven (issue #26: the one
/// deterministic case was missing convergence-driver wiring, which this
/// harness has).
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
///
/// `record_promotable_failures` controls whether a violation on this call
/// gets persisted into `tests/dst_corpus/network_fault_chaos_cases.jsonl`
/// (a tracked file). This must be `true` ONLY from the fresh-sweep loop in
/// `network_fault_chaos_scenario`, which is the one caller that genuinely
/// means "a new failure here is worth promoting into the regression
/// corpus." Every other caller -- the corpus-replay loop (an
/// already-known case failing again is not a NEW case to record; recording
/// it anyway is exactly how the corpus accumulates duplicate entries for
/// the same seed over time) and any ad hoc diagnostic (`batch_position_
/// probe` below, or any future one) -- must pass `false`. This is an
/// explicit parameter, not a default, precisely so a future caller cannot
/// mutate a tracked file without that intent being visible in its own call
/// site: recording used to fire unconditionally two layers down inside
/// `run_scenario`, invisible to every caller, which is what let one
/// diagnostic silently dirty the corpus with no code at its own call site
/// suggesting it could.
fn run_seed_catching_time_limit(
    seed: u64,
    ops_per_run: usize,
    record_promotable_failures: bool,
) -> Result<(), String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_in_madsim(seed, ops_per_run, record_promotable_failures)
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
    // Kept as its own counter, never summed into the fresh-sweep
    // `generated_skipped`/`exercised` accounting below: a corpus infra
    // skip must never count toward the requested `variations` of *fresh*
    // seeds actually exercised, and the final gate must never blame the
    // wrong marker when a corpus replay is what skipped. Mirrors
    // `dst_hydration_under_fault_chaos.rs`'s equivalent split.
    //
    // Skipped entirely when `dst_support::corpus::should_skip_replay()`
    // says this is a targeted run -- see that function's doc comment (a
    // caller pinning down one specific seed has already opted into "just
    // this seed"; a plain untargeted run, what CI performs, still replays
    // the full corpus every time).
    let mut corpus_skipped: u64 = 0;
    if !dst_support::corpus::should_skip_replay() {
        for case in load_corpus_cases() {
            // `false`: an already-recorded case failing again on replay
            // must not be re-appended -- see `run_seed_catching_time_
            // limit`'s doc comment on `record_promotable_failures`.
            match run_seed_catching_time_limit(case.seed, ops_per_run, false) {
                Ok(()) => {}
                Err(e)
                    if e.starts_with(BASELINE_TIMEOUT_MARKER)
                        || e.starts_with(TIME_LIMIT_MARKER)
                        || e.starts_with(RESOURCE_EXHAUSTION_MARKER) =>
                {
                    eprintln!("NETWORK-FAULT corpus infra skip seed {}: {e}", case.seed);
                    corpus_skipped += 1;
                }
                Err(e) => failures.push(format!("[corpus replay] {e}")),
            }
        }
    }

    // An explicit DST_BASE_SEED is a caller pinning down one specific
    // reproduction range -- silently substituting a different seed's
    // outcome for one in that range would defeat the documented
    // DST_BASE_SEED=<seed> DST_VARIATIONS=<n> reproduction recipe, so
    // max_attempts is bounded to exactly the requested range rather than
    // widened. A skip within that exact range still fails the final gate
    // below (it does not retry past the pinned range), which is the
    // correct outcome for a targeted reproduction.
    let targeted = std::env::var("DST_BASE_SEED").is_ok();
    let max_attempts =
        if targeted { variations.max(1) } else { variations.saturating_mul(8).max(8) };

    let mut attempted: u64 = 0;
    let mut exercised: u64 = 0;
    let mut generated_skipped: HashMap<&'static str, u64> = HashMap::new();
    while exercised < variations && attempted < max_attempts {
        let seed = base_seed.wrapping_add(attempted);
        attempted += 1;
        // `true`: this is the one loop that genuinely discovers new
        // failures worth promoting into the corpus -- see
        // `run_seed_catching_time_limit`'s doc comment.
        match run_seed_catching_time_limit(seed, ops_per_run, true) {
            Ok(()) => exercised += 1,
            Err(e)
                if e.starts_with(BASELINE_TIMEOUT_MARKER)
                    || e.starts_with(TIME_LIMIT_MARKER)
                    || e.starts_with(RESOURCE_EXHAUSTION_MARKER) =>
            {
                let kind = if e.starts_with(BASELINE_TIMEOUT_MARKER) {
                    "baseline_timeout"
                } else if e.starts_with(TIME_LIMIT_MARKER) {
                    "time_limit"
                } else {
                    "resource_exhaustion"
                };
                eprintln!("NETWORK-FAULT infra skip seed {seed}: {e}");
                *generated_skipped.entry(kind).or_insert(0) += 1;
            }
            Err(e) => failures.push(e),
        }
    }
    std::panic::set_hook(previous_hook);

    assert!(
        failures.is_empty(),
        "{}/{variations} network-fault chaos variations found an oracle violation \
         (fresh-sweep infra skips={generated_skipped:?}, corpus infra skips={corpus_skipped} -- a \
         round-convergence timeout is no longer skipped -- it appears among the failures below):\n{}\n\
         (reproduce one with DST_BASE_SEED=<seed> DST_VARIATIONS=1 cargo test ... \
         network_fault_chaos_scenario, then narrow to run_scenario(seed, ops) directly)",
        failures.len(),
        failures.join("\n---\n")
    );
    assert!(
        exercised >= variations,
        "requested {variations} exercised network-fault seeds, but exercised only {exercised} \
         after {attempted} attempts; generated skips={generated_skipped:?}, corpus skips={corpus_skipped}"
    );
}

/// Ad hoc diagnostic, not part of the regular gate: isolates whether one
/// target seed's outcome depends on running after a batch of prior
/// network-touching runs in the same process (real thread/resource
/// accumulation), as opposed to being a property of the seed's own content.
///
/// `DST_BATCH_SEEDS` -- comma-separated seeds run first, in order, in this
/// process. Their individual outcome is logged but never affects this
/// test's own verdict -- only `DST_TARGET_SEED`, run last, decides pass/fail.
/// `DST_CHAOS_OPS` is honored the same as the main scenario.
///
/// `#[ignore]`: a plain, unfiltered `cargo test --test dst_network_fault_
/// chaos` (what `dst-lane1`/`dst-lane2` and CI actually run) must keep
/// working with no env vars set. Without this, this test exists in the
/// binary and gets swept up by that default invocation, where it panics
/// immediately on the missing `DST_TARGET_SEED` -- run it explicitly with
/// `--exact batch_position_probe --include-ignored`.
#[test]
#[ignore]
fn batch_position_probe() {
    let ops_per_run: usize = std::env::var("DST_CHAOS_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_OPS_PER_RUN);
    let batch_seeds: Vec<u64> = std::env::var("DST_BATCH_SEEDS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u64>().expect("DST_BATCH_SEEDS: not a valid u64 list"))
        .collect();
    let target_seed: u64 = std::env::var("DST_TARGET_SEED")
        .expect("DST_TARGET_SEED is required")
        .parse()
        .expect("DST_TARGET_SEED: not a valid u64");

    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    // `false` throughout: this is a diagnostic, never a corpus-promotion
    // caller -- see `run_seed_catching_time_limit`'s doc comment on
    // `record_promotable_failures`. A violation here is logged, never
    // persisted.
    for (i, seed) in batch_seeds.iter().enumerate() {
        match run_seed_catching_time_limit(*seed, ops_per_run, false) {
            Ok(()) => eprintln!("batch_position_probe: batch[{i}] seed {seed}: ok"),
            Err(e) => eprintln!("batch_position_probe: batch[{i}] seed {seed}: {e}"),
        }
    }

    let result = run_seed_catching_time_limit(target_seed, ops_per_run, false);
    std::panic::set_hook(previous_hook);

    match result {
        Ok(()) => {}
        Err(e) => panic!(
            "target seed {target_seed} failed after a {}-run batch in this process: {e}",
            batch_seeds.len()
        ),
    }
}

/// One authenticated QUIC connection between two loopback endpoints, as a
/// channel on each side. The real transport, so a simulated run exercises
/// what ships rather than a substitute for it.
async fn quic_channel_pair(
    socket_a: tokio::net::UdpSocket,
    socket_b: tokio::net::UdpSocket,
) -> (
    std::sync::Arc<yadorilink_transport::QuicPeerChannel>,
    std::sync::Arc<yadorilink_transport::QuicPeerChannel>,
) {
    use yadorilink_transport::{
        ConnectRole, DeviceSigningKeyPair, QuicPeerChannel, QuicPeerEndpoint, TransportHub,
    };
    let addr_b = socket_b.local_addr().unwrap();
    let key_a = DeviceSigningKeyPair::generate();
    let key_b = DeviceSigningKeyPair::generate();
    let public_a = key_a.public_bytes();
    let public_b = key_b.public_bytes();
    let endpoint_a = QuicPeerEndpoint::new(TransportHub::from_socket(socket_a), key_a).unwrap();
    let endpoint_b = QuicPeerEndpoint::new(TransportHub::from_socket(socket_b), key_b).unwrap();
    endpoint_a.authorize(public_b);
    endpoint_b.authorize(public_a);
    let accepting = {
        let endpoint_b = endpoint_b.clone();
        tokio::spawn(async move { endpoint_b.accept(public_a).await })
    };
    let dialed = endpoint_a.connect(addr_b, public_b).await.unwrap();
    let accepted = accepting.await.unwrap().unwrap();
    (
        QuicPeerChannel::new(dialed, ConnectRole::Dial),
        QuicPeerChannel::new(accepted, ConnectRole::Accept),
    )
}
