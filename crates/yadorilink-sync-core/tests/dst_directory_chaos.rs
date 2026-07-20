//! Directory + rename/move DST fuzz sweep (extends `dst_two_device_chaos.rs`
//! into territory that scenario deliberately never touches: nested paths,
//! file rename/move, and whole-directory rename). Copies that file's
//! structure almost verbatim (`ChaosDevice`, `setup_device`,
//! `connect_sessions`, `converge_path`'s multi-path generalization,
//! `content_for`, the seed-sweep/`catch_unwind`/marker-classification
//! scaffolding) rather than reinventing it — see that file's own doc
//! comment for the rationale behind each piece this one reuses unchanged,
//! including the change-history-DAG propagation both scenarios drive: a signed
//! `ChangeEmitter` per device, and `announce_local_commit` (not an index push)
//! to hand a committed edit to the peer, whose `run()` loop pulls the ancestry
//! it is missing and materializes the same state.
//!
//! What's new here, and why it's the fragile area `dst_two_device_chaos.rs`
//! doesn't cover: that scenario's `CANDIDATE_PATHS` are three flat,
//! never-renamed top-level files — every op is a write or delete *of the
//! same path string*. A rename/move has no dedicated wire message (see
//! `local_change.rs`'s module doc comment: content-addressing makes a
//! rename "free" to transfer, but the index has no rename *identity* —
//! it's always modeled as `Removed(old path)` + `CreatedOrModified(new
//! path)`, two independent index rows). A whole-directory rename is even
//! more special-cased: `watcher.rs`'s `RenameMode::From` reports only the
//! vacated *directory* path as a single `Removed` event (nothing
//! synthesizes one event per child), and `local_change.rs`'s
//! `LocalChangeOutcome::FilesChanged` cascade is what turns that single
//! event into a tombstone for every live index row nested under it. None
//! of this is
//! exercised anywhere in the existing DST suite. This file drives it
//! directly, both solo (uncontested) and racing (concurrent with a peer's
//! independent change to the same file/directory), looking for the
//! non-convergence/data-loss/duplicate-conflict-copy bugs this
//! rename-as-delete-plus-create, cascade-on-a-single-event design predicts
//! as likely.
//!
//! **Oracle model for a rename/move.** Because a renamed path is a brand
//! new index key with no causal relationship to the old one, this driver
//! records every rename/move as exactly the two independent history
//! entries the real system produces: a delete of the old path (from that
//! path's own running baseline) and a write of the new path (starting
//! fresh, since it's a key nobody has ever written before) carrying the
//! *same* `content_id` as before (the bytes don't change). Two devices
//! racing a rename of the *same* source to *different* targets therefore
//! never contends at the index level at all — it manifests as one shared
//! concurrent delete of the old key (harmless, no survival requirement on
//! either side of a delete-delete race) plus two entirely independent
//! writes to two different new keys, each of which must independently
//! survive per `check_no_loss`. Whether both keys legitimately end up
//! present forever (an emergent "rename doesn't have cross-device atomicity"
//! duplication) or one is silently dropped (a genuine bug) is exactly what
//! this scenario's oracle checks are built to tell apart.
//!
//! Every check runs the **recursive** oracle variants
//! (`check_convergence_recursive`/`check_no_loss_recursive`/`check_conflict_
//! copy_accounting_recursive`/`check_no_corruption_recursive`, added
//! alongside this file in `dst_support/oracle.rs`) since every path here
//! can be nested — the flat, root-only originals would silently miss an
//! entire subtree.
//!
//! # THIS FILE IS RED. It must not gate CI yet. Read this before "fixing" it.
//!
//! 18 of the 30 default variations fail (0 skipped): 15 are a round-level "never
//! converged" (the per-round gate below timing out on a path whose bytes never
//! agree), plus 6 terminal `Convergence`, 2 `StructuralIndexDiskMismatch` and 1
//! `NoLoss`. The observed state is a path left **live in the index with no file
//! on disk** — e.g. seed 3509503757 (`DST_BASE_SEED` 0xD12E_C700 + 13) stalls at
//! round 1 on `dir2/c.bin`. The failing offsets from 0xD12E_C700 are {1, 2, 4,
//! 6, 7, 8, 9, 10, 12, 13, 14, 15, 17, 18, 22, 23, 27, 28}.
//!
//! **What is and is not established about that red.** The honest summary is that
//! the change-history DAG did not cause it, and neither did anything else in
//! this file's migration:
//!
//!   - The gap is **pre-existing and engine-independent**. Isolating the two
//!     things this file's migration changed at once — propagation (legacy ->
//!     DAG) and the per-round gate (version-vector equality -> on-disk byte
//!     comparison) — shows the whole delta is the *gate*. Holding the LEGACY
//!     engine and swapping only the gate to bytes already fails 18/30 with 15
//!     never-converged; the migrated DAG with the byte gate fails 18/30 with the
//!     same counts, classes, seeds, rounds and paths. The DAG changes nothing
//!     here.
//!   - It is **not** true that these seeds simply "failed before too". With the
//!     shipped vector gate the same base fails 12/30 with *zero*
//!     never-converged. The extra seeds are ones that genuinely passed before —
//!     but they passed for a bad reason: the vector gate compared index rows to
//!     index rows, so it was structurally blind to exactly the index-vs-disk
//!     disagreement that is the bug. It reported convergence while the bytes
//!     underneath still disagreed, which is what let those runs reach the
//!     terminal oracles at all.
//!
//! So the byte gate is not what to weaken to get green: it is the entire value
//! of the migration, and it unmasked a real convergence gap that predates it on
//! both engines. The gap itself needs its own investigation and is deliberately
//! not addressed here; no oracle is weakened to hide it.

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
use dst_support::case_ir::ContentTable;
use dst_support::clock::HarnessClock;
use dst_support::oracle::GlobalOracle;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::debounce::{self, DebounceConfig, FlushPathRequest};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::peer_session::{PeerSyncSession, PendingLocalChangeFlush};
use yadorilink_sync_core::version_vector::VersionVector;
use yadorilink_sync_core::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource,
};
use yadorilink_transport::PeerChannel;

const GROUP_ID: &str = "dst-dir-chaos-group";
const CANARY_PATH: &str = "startup-canary.bin";
/// Comfortably above `DebounceConfig::DEFAULT_QUIET_PERIOD` (300ms) plus
/// flush -> index -> heads-announce -> peer-pull margin, exactly
/// `dst_two_device_chaos.rs`'s `ROUND_SETTLE` (see that file's doc
/// comment for the full reasoning).
const ROUND_SETTLE: Duration = Duration::from_millis(400);
/// Mirrors `dst_two_device_chaos.rs`'s `RACE_INNER_DELAY` exactly.
const RACE_INNER_DELAY: Duration = Duration::from_millis(20);
const RACE_SETTLE: Duration = Duration::from_millis(500);
const DEFAULT_OPS_PER_RUN: usize = 12;
const DEFAULT_VARIATIONS: u64 = 30;
const BASELINE_TIMEOUT_MARKER: &str = "BASELINE_TIMEOUT: ";

/// Identical role to `dst_two_device_chaos.rs`'s `ChaosDevice` — always
/// wired with `PendingLocalChangeFlush` on both devices, production-
/// representative configuration.
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
                        // Emitter appended the signed change; announce heads so
                        // the peer pulls it over the DAG.
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
                    if std::env::var("DST_DIR_CHAOS_DEBUG").is_ok() && !outcome.records.is_empty() {
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
                    if std::env::var("DST_DIR_CHAOS_DEBUG").is_ok() {
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

/// Same rationale/value as `dst_two_device_chaos.rs`'s identical constant:
/// generous enough to tolerate the self-echo re-index hydration-timeout
/// churn without false-failing round progression; production has no
/// "N seconds or fail" gate, only eventual consistency.
// This is now the *budget*
// `converge_paths` hands to the shared `settle_until` primitive, not a
// hand-rolled poll gate -- the rationale above still governs the value.
const ROUND_SETTLE_BUDGET: Duration = Duration::from_secs(45);
const CONVERGENCE_PROMPTNESS_SLA: Duration = Duration::from_secs(3);
/// Same rationale/value as `dst_two_device_chaos.rs`'s identical constant:
/// the budget the shared `dst_support::settle::settle_recursive` primitive
/// polls the recursive convergence oracle against at this scenario's
/// terminal quiescence point.
const FINAL_CONVERGENCE_BUDGET: Duration = Duration::from_secs(60);

/// Generalizes `dst_two_device_chaos.rs`'s single-path `converge_path` to
/// a *set* of paths, gated once (not once per path — avoids multiplying
/// the wait bound by however many paths a directory-level op happens to
/// touch). See that file's `converge_path` doc comment for the full
/// rationale of why this proof-of-common-base is required before every
/// round that reuses a path a prior round already touched, and for why the
/// gate compares on-disk bytes rather than version vectors (a DAG-materialized
/// record carries an empty `VersionVector`, so vector equality is
/// unsatisfiable for a propagated path).
async fn converge_paths(
    device_a: &ChaosDevice,
    device_b: &ChaosDevice,
    paths: &[String],
) -> (bool, Duration) {
    let outcome = dst_support::settle::settle_until(ROUND_SETTLE_BUDGET, || {
        paths.iter().all(|path| {
            let a = std::fs::read(device_a.root.join(path)).ok();
            let b = std::fs::read(device_b.root.join(path)).ok();
            a == b
        })
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

    // Same DAG propagation as `dst_two_device_chaos.rs`'s `connect_sessions`,
    // for the same reason: each device materializes a conflict copy locally
    // from the shared change set, so the legacy `broadcast_change`-shaped
    // forwarding channel has nothing left to carry and is dropped.
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

fn basename(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
}

fn parent_dir(path: &str) -> String {
    match Path::new(path).parent() {
        Some(p) if p != Path::new("") => p.to_string_lossy().to_string(),
        _ => String::new(),
    }
}

// -- Directory-op-aware local-write appliers, mirroring
// `dst_two_device_chaos.rs`'s `deliver_local_write`/`deliver_local_delete`/
// `apply_and_push`, generalized to (a) nested/dynamic (not `'static`)
// paths and (b) rename/move/whole-directory-rename shapes those flat
// helpers never needed. --

/// Writes new content at (possibly nested) `path`, creating parent
/// directories as needed, then delivers a `CreatedOrModified` watcher
/// event -- the "pending, sitting in this device's own debounce
/// accumulator" side of a race, or an ordinary solo write.
async fn deliver_local_write(
    device: &Arc<ChaosDevice>,
    path: &str,
    content: &[u8],
    clock: &HarnessClock,
) -> Result<(), String> {
    let full_path = device.root.join(path);
    if let Some(parent) = full_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    // Gap A: `fs_ops::write` writes and stamps the mtime through the shared
    // `HarnessClock` in one step -- no local `stamp_deterministic_mtime`.
    dst_support::fs_ops::write(clock, &full_path, content)?;
    device
        .events_tx
        .send(FsChangeEvent { path: full_path, kind: FsChangeKind::CreatedOrModified })
        .await
        .map_err(|_| "watcher channel closed early".to_string())
}

async fn deliver_local_delete(device: &Arc<ChaosDevice>, path: &str) -> Result<(), String> {
    // `fs_ops::remove` tolerates a concurrent removal exactly as the old
    // local `remove_file_if_present` did.
    dst_support::fs_ops::remove(&device.root.join(path))?;
    device
        .events_tx
        .send(FsChangeEvent { path: device.root.join(path), kind: FsChangeKind::Removed })
        .await
        .map_err(|_| "watcher channel closed early".to_string())
}

/// Delivers every watch event `dst_support::fs_events::decompose` derives
/// from `op` -- the shared
/// single source of truth for a rename/whole-directory-rename's classified
/// event sequence, pinned against the real notify-backed watcher by
/// `watcher_decompose_conformance.rs` so this scenario's event shapes can't
/// silently drift from `watcher.rs`'s own classification.
async fn deliver_decomposed(
    device: &Arc<ChaosDevice>,
    op: &dst_support::fs_events::FsOp,
) -> Result<(), String> {
    for ev in dst_support::fs_events::decompose(op) {
        device
            .events_tx
            .send(FsChangeEvent { path: device.root.join(&ev.path), kind: ev.kind })
            .await
            .map_err(|_| "watcher channel closed early".to_string())?;
    }
    Ok(())
}

/// Renames/moves a single file on disk (creating the destination's parent
/// directory if this is a cross-directory move), then delivers the
/// `Removed(old)` + `CreatedOrModified(new)` event pair via `deliver_
/// decomposed` -- exactly how `watcher.rs`'s `RenameMode::Both` classifies
/// a real rename (see this file's module doc comment).
async fn deliver_local_rename(
    device: &Arc<ChaosDevice>,
    old_path: &str,
    new_path: &str,
    clock: &HarnessClock,
) -> Result<(), String> {
    let old_full = device.root.join(old_path);
    let new_full = device.root.join(new_path);
    if let Some(parent) = new_full.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    dst_support::fs_ops::rename(clock, &old_full, &new_full)?;
    deliver_decomposed(
        device,
        &dst_support::fs_events::FsOp::Rename {
            from: old_path.to_string(),
            to: new_path.to_string(),
        },
    )
    .await
}

/// Renames a whole directory (`old_dir` -> `new_dir`) on disk, then
/// delivers `Removed(old_dir)` (the single event a real watcher produces
/// for the vacated directory itself -- `local_change.rs`'s orphan cascade
/// is what turns this into a tombstone for every live index row nested
/// under it) followed by
/// one `CreatedOrModified` per `children` (their basenames under
/// `old_dir`) at their new location under `new_dir`, via `deliver_
/// decomposed`.
async fn deliver_local_dir_rename(
    device: &Arc<ChaosDevice>,
    old_dir: &str,
    new_dir: &str,
    children: &[String],
    clock: &HarnessClock,
) -> Result<(), String> {
    let old_full = device.root.join(old_dir);
    let new_full = device.root.join(new_dir);
    if let Some(parent) = new_full.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&old_full, &new_full).map_err(|e| e.to_string())?;
    for child in children {
        let _ = dst_support::fs_ops::set_mtime(clock, &new_full.join(child));
    }
    deliver_decomposed(
        device,
        &dst_support::fs_events::FsOp::DirRename {
            from_dir: old_dir.to_string(),
            to_dir: new_dir.to_string(),
            children: children.to_vec(),
        },
    )
    .await
}

async fn deliver_local_mkdir(device: &Arc<ChaosDevice>, dir_path: &str) -> Result<(), String> {
    let full = device.root.join(dir_path);
    std::fs::create_dir_all(&full).map_err(|e| e.to_string())?;
    device
        .events_tx
        .send(FsChangeEvent { path: full, kind: FsChangeKind::CreatedOrModified })
        .await
        .map_err(|_| "watcher channel closed early".to_string())
}

async fn deliver_local_rmdir(device: &Arc<ChaosDevice>, dir_path: &str) -> Result<(), String> {
    let full = device.root.join(dir_path);
    match std::fs::remove_dir(&full) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    device
        .events_tx
        .send(FsChangeEvent { path: full, kind: FsChangeKind::Removed })
        .await
        .map_err(|_| "watcher channel closed early".to_string())
}

/// Applies one event directly (bypassing this device's own debounce) and
/// pushes the result -- the "other side" of a race, mirroring
/// `dst_two_device_chaos.rs`'s `apply_and_push`. Caller has already
/// mutated disk (write/rename/delete) before calling this.
async fn apply_and_push(
    device: &Arc<ChaosDevice>,
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
    if let LocalChangeOutcome::FileChanged(_record) = &outcome {
        if let Some(session) = device.session.get() {
            // `process_event` (emitter set) appended the signed change; announce
            // heads so the peer pulls it over the DAG.
            session.announce_local_commit(GROUP_ID).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(outcome)
}

/// Directly applies a single-file rename/move (`Removed(old)` +
/// `CreatedOrModified(new)`), pushing both resulting records in one
/// batch. Caller has already performed the on-disk rename.
///
/// Not currently exercised by any of this file's five race scenarios
/// (each one's "applied immediately" side does a write or delete, never
/// a rename) -- kept as a documented, ready-to-use primitive alongside
/// its `deliver_local_rename` (pending-side) sibling, matching this
/// file's other appliers.
#[allow(dead_code)]
async fn apply_and_push_rename(
    device: &Arc<ChaosDevice>,
    old_path: &str,
    new_path: &str,
) -> Result<(), String> {
    let mut records = Vec::new();
    let op = dst_support::fs_events::FsOp::Rename {
        from: old_path.to_string(),
        to: new_path.to_string(),
    };
    for ev in dst_support::fs_events::decompose(&op) {
        let outcome = device
            .processor
            .process_event(
                GROUP_ID,
                &device.root,
                &FsChangeEvent { path: device.root.join(&ev.path), kind: ev.kind },
            )
            .await
            .map_err(|e| e.to_string())?;
        match outcome {
            LocalChangeOutcome::FileChanged(r) => records.push(r),
            LocalChangeOutcome::FilesChanged(rs) => records.extend(rs),
            _ => {}
        }
    }
    if !records.is_empty() {
        if let Some(session) = device.session.get() {
            // Every `process_event` above appended its signed change in the same
            // transaction as its index write; one announce covers the whole
            // decomposed batch (the peer pulls the full ancestry either way).
            session.announce_local_commit(GROUP_ID).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Directly applies a whole-directory rename (`Removed(old_dir)` +
/// `CreatedOrModified` per child), pushing every resulting record
/// (including the cascade's `FilesChanged` batch) in one push. Caller has
/// already performed the on-disk rename. Sources its event sequence from
/// `dst_support::fs_events::decompose` (Gap D), same as `deliver_decomposed`.
async fn apply_and_push_dir_rename(
    device: &Arc<ChaosDevice>,
    old_dir: &str,
    new_dir: &str,
    children: &[String],
) -> Result<(), String> {
    let mut records = Vec::new();
    let op = dst_support::fs_events::FsOp::DirRename {
        from_dir: old_dir.to_string(),
        to_dir: new_dir.to_string(),
        children: children.to_vec(),
    };
    for ev in dst_support::fs_events::decompose(&op) {
        let outcome = device
            .processor
            .process_event(
                GROUP_ID,
                &device.root,
                &FsChangeEvent { path: device.root.join(&ev.path), kind: ev.kind },
            )
            .await
            .map_err(|e| e.to_string())?;
        match outcome {
            LocalChangeOutcome::FileChanged(r) => records.push(r),
            LocalChangeOutcome::FilesChanged(rs) => records.extend(rs),
            _ => {}
        }
    }
    if !records.is_empty() {
        if let Some(session) = device.session.get() {
            // Every `process_event` above appended its signed change in the same
            // transaction as its index write; one announce covers the whole
            // decomposed batch (the peer pulls the full ancestry either way).
            session.announce_local_commit(GROUP_ID).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn content_for(seed: u64, round: usize, device_id: &str, tag: &str) -> Vec<u8> {
    format!("seed {seed} round {round} {tag} {device_id}").into_bytes()
}

// -- Oracle-bookkeeping helpers: register a fresh content value, and
// record a write/delete at a path from its own running baseline (fresh if
// this is the first time the path is ever touched -- a rename's
// destination and a solo path both go through the same code, since
// `HashMap::get` returning `None` on a brand-new key already yields
// `VersionVector::default` via `unwrap_or_default`). Races derive `x`'s
// and `y`'s versions manually from one shared captured base instead
// (mirroring `dst_two_device_chaos.rs`'s Race arm exactly) since both
// must start from the *same* pre-race point, not be threaded through
// these sequential helpers. --

fn register_content(content_table: &mut ContentTable, next_id: &mut u64, bytes: Vec<u8>) -> u64 {
    let id = *next_id;
    *next_id += 1;
    content_table.insert(id, bytes);
    id
}

fn record_write_at(
    oracle: &mut GlobalOracle,
    path_baseline: &mut HashMap<String, VersionVector>,
    path: &str,
    device_idx: usize,
    device_id: &str,
    content_id: u64,
) -> VersionVector {
    let mut v = path_baseline.get(path).cloned().unwrap_or_default();
    v.increment(device_id);
    oracle.record_write(path, device_idx, content_id, v.clone());
    path_baseline.insert(path.to_string(), v.clone());
    v
}

fn record_delete_at(
    oracle: &mut GlobalOracle,
    path_baseline: &mut HashMap<String, VersionVector>,
    path: &str,
    device_idx: usize,
    device_id: &str,
) -> VersionVector {
    let mut v = path_baseline.get(path).cloned().unwrap_or_default();
    v.increment(device_id);
    oracle.record_delete(path, device_idx, v.clone());
    path_baseline.insert(path.to_string(), v.clone());
    v
}

/// **Model state, agmsg-review fix.** `all_files` is the complete set of
/// every content-bearing path this scenario has ever created and not yet
/// deleted (path -> content_id), *including* a race's "independent" loser
/// side that no future round ever targets directly again. `active` is the
/// subset eligible for a future round's own solo/race target selection --
/// a strict subset of `all_files`'s keys.
///
/// The split matters for directory-rename cascade *discovery*: an early
/// version of this scenario derived a directory-rename's affected
/// children only from `active`, which under-counted any independent
/// survivor (e.g. race (c)'s losing side) that happened to physically
/// share that directory -- a real `std::fs::rename` of the whole
/// directory moves such a file's *bytes* regardless, but with no
/// synthesized watcher event for it, neither device's index (nor this
/// scenario's own oracle history, which had no record of where it went)
/// ever learns its new location, producing a permanent, purely-harness-
/// induced tree divergence indistinguishable from a real non-convergence
/// bug. Production's real watcher does not have this gap:
/// `watcher.rs`'s `reconcile_new_directory_subtree` walks a newly-
/// registered directory's *actual* disk contents (via `walkdir`) and
/// synthesizes a `CreatedOrModified` for everything it finds, exactly
/// this scenario's `all_files`-prefix-scan counterpart. A directory-
/// rename cascade here scans `all_files` (not `active`) for the old
/// prefix so every affected file -- tracked-for-reuse or independent --
/// gets both its watcher event *and* its oracle history correctly
/// carried over to the new path.
fn pick_active_idx(rng: &mut StdRng, active: &[String]) -> usize {
    rng.random_range(0..active.len())
}

/// Every entry in `all_files` whose path sits directly under `dir`
/// (i.e. `dir/<basename>`, no further nesting -- this scenario never
/// creates directories more than one level deep), paired with its
/// current content_id. Used by every directory-rename branch (solo and
/// races) to discover the *complete* set of affected files -- see
/// `pick_active_idx`'s doc comment for why this must be `all_files`, not
/// just `active`.
fn siblings_under(all_files: &HashMap<String, u64>, dir: &str) -> Vec<(String, u64)> {
    all_files.iter().filter(|(p, _)| parent_dir(p) == dir).map(|(p, id)| (p.clone(), *id)).collect()
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
    let recovery_store_a = store_a.clone();
    let recovery_store_b = store_b.clone();
    connect_sessions(&mut rng, &device_a, state_a, store_a, &device_b, state_b, store_b).await;

    // Startup gate, identical purpose to `dst_two_device_chaos.rs`'s: prove
    // the connection is actually up before the randomized rounds begin.
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

    let mut content_table = ContentTable::default();
    let mut next_content_id: u64 = 0;
    content_table.insert(next_content_id, b"canary".to_vec());
    next_content_id += 1;
    let mut oracle = GlobalOracle::new();
    let mut path_baseline: HashMap<String, VersionVector> = HashMap::new();
    let debug = std::env::var("DST_DIR_CHAOS_DEBUG").is_ok();
    let device_idx_of = |device: &ChaosDevice| -> usize {
        if std::ptr::eq(device, device_a.as_ref()) {
            0
        } else {
            1
        }
    };

    // The one seed-derived,
    // strictly-monotonic synthetic "now" for this run, owned by
    // `dst_support::clock::HarnessClock` -- see `dst_two_device_chaos.rs`'s
    // identical `clock` binding for the full rationale (now lives in
    // `clock.rs`). `fs_ops::write`/`fs_ops::rename` stamp every tempdir
    // mutation through it, so a forgotten stamp is unrepresentable rather
    // than a reviewer convention (the pre-migration per-scenario
    // `stamp_deterministic_mtime` state).
    let clock = HarnessClock::from_seed(seed);
    clock.install_as_session_clock();

    // Seed three initial nested files (matching this file's own doc
    // comment's `dir1/a.bin`, `dir1/b.bin`, `dir2/c.bin` example) via
    // device A -- a mini "solo write" each, registered the same way any
    // later round's solo write is. Directories come along for free
    // (`deliver_local_write` creates parent dirs; `reconstruct_file`/
    // `write_placeholder` on the receiving side do the same, per
    // `chunker.rs`).
    let mut all_files: HashMap<String, u64> = HashMap::new();
    let mut active: Vec<String> = Vec::new();
    for (idx, init_path) in ["dir1/a.bin", "dir1/b.bin", "dir2/c.bin"].iter().enumerate() {
        let device = if idx == 2 { &device_b } else { &device_a };
        let content = content_for(seed, 0, &device.device_id, &format!("init-{init_path}"));
        deliver_local_write(device, init_path, &content, &clock).await?;
        tokio::time::sleep(ROUND_SETTLE).await;
        let content_id = register_content(&mut content_table, &mut next_content_id, content);
        record_write_at(
            &mut oracle,
            &mut path_baseline,
            init_path,
            device_idx_of(device),
            &device.device_id,
            content_id,
        );
        all_files.insert(init_path.to_string(), content_id);
        active.push(init_path.to_string());
    }

    for round in 0..ops_per_run {
        // +1s per round so even a delete-only round (which stamps nothing)
        // still advances the shared timeline; write rounds advance it
        // further via `fs_ops` stamping on every mutation.
        clock.tick_round();

        // Top-up: keep at least 2 active paths so every branch below
        // always has a valid target -- a race can retire a path from
        // `active` (moving it to independent-only tracking in
        // `all_files`), so the active pool can shrink; this tops it back
        // up with an ordinary solo write before this round's own
        // randomized op, rather than letting a later round find nothing
        // to act on.
        while active.len() < 2 {
            let device = if rng.random_bool(0.5) { &device_a } else { &device_b };
            let path = format!("topup-r{round}-{}.bin", active.len());
            let content = content_for(seed, round, &device.device_id, "topup");
            deliver_local_write(device, &path, &content, &clock).await?;
            tokio::time::sleep(ROUND_SETTLE).await;
            let content_id = register_content(&mut content_table, &mut next_content_id, content);
            record_write_at(
                &mut oracle,
                &mut path_baseline,
                &path,
                device_idx_of(device),
                &device.device_id,
                content_id,
            );
            all_files.insert(path.clone(), content_id);
            active.push(path);
        }

        let kind_roll = rng.random_range(0..100);
        if debug {
            eprintln!("seed {seed} round {round}: kind_roll={kind_roll} active={active:?}");
        }

        match kind_roll {
            // Solo write/edit (10%): overwrite an existing path's content
            // in place.
            0..=9 => {
                let idx = pick_active_idx(&mut rng, &active);
                let device = if rng.random_bool(0.5) { &device_a } else { &device_b };
                let content = content_for(seed, round, &device.device_id, "solo-write");
                let path = active[idx].clone();
                let (converged, elapsed) =
                    converge_paths(&device_a, &device_b, &[path.clone()]).await;
                oracle.record_round_convergence_latency(&path, elapsed);
                if !converged {
                    return Err(format!("seed {seed}: round {round}, path {path} never converged across both devices within the poll timeout"));
                }
                deliver_local_write(device, &path, &content, &clock).await?;
                tokio::time::sleep(ROUND_SETTLE).await;
                let content_id =
                    register_content(&mut content_table, &mut next_content_id, content);
                record_write_at(
                    &mut oracle,
                    &mut path_baseline,
                    &path,
                    device_idx_of(device),
                    &device.device_id,
                    content_id,
                );
                all_files.insert(path, content_id);
            }
            // Solo rename within the same directory (10%).
            10..=19 => {
                let idx = pick_active_idx(&mut rng, &active);
                let device = if rng.random_bool(0.5) { &device_a } else { &device_b };
                let old_path = active[idx].clone();
                let (converged, elapsed) =
                    converge_paths(&device_a, &device_b, &[old_path.clone()]).await;
                oracle.record_round_convergence_latency(&old_path, elapsed);
                if !converged {
                    return Err(format!("seed {seed}: round {round}, path {old_path} never converged across both devices within the poll timeout"));
                }
                let content_id = all_files[&old_path];
                let dir = parent_dir(&old_path);
                let new_path = if dir.is_empty() {
                    format!("renamed-r{round}.bin")
                } else {
                    format!("{dir}/renamed-r{round}.bin")
                };
                deliver_local_rename(device, &old_path, &new_path, &clock).await?;
                tokio::time::sleep(ROUND_SETTLE).await;
                record_delete_at(
                    &mut oracle,
                    &mut path_baseline,
                    &old_path,
                    device_idx_of(device),
                    &device.device_id,
                );
                record_write_at(
                    &mut oracle,
                    &mut path_baseline,
                    &new_path,
                    device_idx_of(device),
                    &device.device_id,
                    content_id,
                );
                all_files.remove(&old_path);
                all_files.insert(new_path.clone(), content_id);
                active[idx] = new_path;
            }
            // Solo move across directories (10%): alternate between the
            // two named top-level directories this file's doc comment
            // uses as its running example.
            20..=29 => {
                let idx = pick_active_idx(&mut rng, &active);
                let device = if rng.random_bool(0.5) { &device_a } else { &device_b };
                let old_path = active[idx].clone();
                let (converged, elapsed) =
                    converge_paths(&device_a, &device_b, &[old_path.clone()]).await;
                oracle.record_round_convergence_latency(&old_path, elapsed);
                if !converged {
                    return Err(format!("seed {seed}: round {round}, path {old_path} never converged across both devices within the poll timeout"));
                }
                let content_id = all_files[&old_path];
                let dest_dir = if old_path.starts_with("dir1/") { "dir2" } else { "dir1" };
                let new_path = format!("{dest_dir}/{}", basename(&old_path));
                deliver_local_rename(device, &old_path, &new_path, &clock).await?;
                tokio::time::sleep(ROUND_SETTLE).await;
                record_delete_at(
                    &mut oracle,
                    &mut path_baseline,
                    &old_path,
                    device_idx_of(device),
                    &device.device_id,
                );
                record_write_at(
                    &mut oracle,
                    &mut path_baseline,
                    &new_path,
                    device_idx_of(device),
                    &device.device_id,
                    content_id,
                );
                all_files.remove(&old_path);
                all_files.insert(new_path.clone(), content_id);
                active[idx] = new_path;
            }
            // Solo delete (5%): retires the path entirely.
            30..=34 => {
                let idx = pick_active_idx(&mut rng, &active);
                let device = if rng.random_bool(0.5) { &device_a } else { &device_b };
                let path = active[idx].clone();
                let (converged, elapsed) =
                    converge_paths(&device_a, &device_b, &[path.clone()]).await;
                oracle.record_round_convergence_latency(&path, elapsed);
                if !converged {
                    return Err(format!("seed {seed}: round {round}, path {path} never converged across both devices within the poll timeout"));
                }
                deliver_local_delete(device, &path).await?;
                tokio::time::sleep(ROUND_SETTLE).await;
                record_delete_at(
                    &mut oracle,
                    &mut path_baseline,
                    &path,
                    device_idx_of(device),
                    &device.device_id,
                );
                all_files.remove(&path);
                active.remove(idx);
            }
            // Solo whole-directory rename (10%): renames every file
            // `all_files` currently tracks under the chosen path's
            // directory in one cascade -- the "rename a directory with
            // its contents" op. Deliberately scans `all_files` (every
            // content-bearing path), not just `active`, so an
            // independent survivor from an earlier race that happens to
            // share this directory is correctly carried over too -- see
            // `pick_active_idx`'s doc comment.
            35..=44 => {
                let idx = pick_active_idx(&mut rng, &active);
                let old_dir = parent_dir(&active[idx]);
                let siblings = siblings_under(&all_files, &old_dir);
                let touched: Vec<String> = siblings.iter().map(|(p, _)| p.clone()).collect();
                // agmsg investigation fix: gate a whole-directory OS-level
                // rename on convergence of *every* path this scenario has
                // ever touched (`path_baseline`'s full key set), not just
                // `touched` (the directory's *currently modeled* children).
                // A real `std::fs::rename` moves every file physically
                // present under the directory on this specific device's
                // disk -- including a stale leftover from an *earlier*
                // round's move-away that hasn't finished materializing
                // (removing the old file / writing the new one) on this
                // device yet, even though this scenario's own model
                // already considers it relocated elsewhere. Without this,
                // that leftover gets dragged along to a name neither this
                // scenario's bookkeeping nor (transiently) either device's
                // index expects, producing a tree divergence that is a
                // harness gating gap, not a product bug (confirmed via
                // seed 3509503759: `dir-r4-y/x-0.bin` existed only on one
                // device because `newdir-r0`'s round-2 move-away of
                // `x-0.bin` to `dir-r2/x-0.bin` had not yet fully
                // materialized on that device when round 4 renamed
                // `newdir-r0` again).
                let full_gate: Vec<String> = path_baseline.keys().cloned().collect();
                let (converged, elapsed) = converge_paths(&device_a, &device_b, &full_gate).await;
                for p in &touched {
                    oracle.record_round_convergence_latency(p, elapsed);
                }
                if !converged {
                    return Err(format!("seed {seed}: round {round}, paths {touched:?} never converged across both devices within the poll timeout"));
                }
                let device = if rng.random_bool(0.5) { &device_a } else { &device_b };
                let new_dir = format!("dir-r{round}");
                let children: Vec<String> = siblings.iter().map(|(p, _)| basename(p)).collect();
                deliver_local_dir_rename(device, &old_dir, &new_dir, &children, &clock).await?;
                tokio::time::sleep(ROUND_SETTLE).await;
                for (old_path, content_id) in &siblings {
                    let new_path = format!("{new_dir}/{}", basename(old_path));
                    record_delete_at(
                        &mut oracle,
                        &mut path_baseline,
                        old_path,
                        device_idx_of(device),
                        &device.device_id,
                    );
                    record_write_at(
                        &mut oracle,
                        &mut path_baseline,
                        &new_path,
                        device_idx_of(device),
                        &device.device_id,
                        *content_id,
                    );
                    all_files.remove(old_path);
                    all_files.insert(new_path.clone(), *content_id);
                    if let Some(a) = active.iter_mut().find(|p| *p == old_path) {
                        *a = new_path;
                    }
                }
            }
            // Solo mkdir + rmdir round-trip (5%): a scratch directory
            // that never holds tracked content -- exercises both
            // appliers without any oracle bookkeeping.
            45..=49 => {
                let device = if rng.random_bool(0.5) { &device_a } else { &device_b };
                let dir_path = format!("scratch-r{round}");
                deliver_local_mkdir(device, &dir_path).await?;
                tokio::time::sleep(ROUND_SETTLE).await;
                deliver_local_rmdir(device, &dir_path).await?;
                tokio::time::sleep(ROUND_SETTLE).await;
            }
            // Race (a) (10%): both devices rename the SAME directory to
            // two DIFFERENT names -- the highest-value directory race.
            // Neither target key contends with the other (different
            // paths), so this exercises whether the shared-source cascade
            // races safely, not classic per-path conflict resolution.
            50..=59 => {
                let idx = pick_active_idx(&mut rng, &active);
                let old_dir = parent_dir(&active[idx]);
                let siblings = siblings_under(&all_files, &old_dir);
                let touched: Vec<String> = siblings.iter().map(|(p, _)| p.clone()).collect();
                // agmsg investigation fix: gate a whole-directory OS-level
                // rename on convergence of *every* path this scenario has
                // ever touched (`path_baseline`'s full key set), not just
                // `touched` (the directory's *currently modeled* children).
                // A real `std::fs::rename` moves every file physically
                // present under the directory on this specific device's
                // disk -- including a stale leftover from an *earlier*
                // round's move-away that hasn't finished materializing
                // (removing the old file / writing the new one) on this
                // device yet, even though this scenario's own model
                // already considers it relocated elsewhere. Without this,
                // that leftover gets dragged along to a name neither this
                // scenario's bookkeeping nor (transiently) either device's
                // index expects, producing a tree divergence that is a
                // harness gating gap, not a product bug (confirmed via
                // seed 3509503759: `dir-r4-y/x-0.bin` existed only on one
                // device because `newdir-r0`'s round-2 move-away of
                // `x-0.bin` to `dir-r2/x-0.bin` had not yet fully
                // materialized on that device when round 4 renamed
                // `newdir-r0` again).
                let full_gate: Vec<String> = path_baseline.keys().cloned().collect();
                let (converged, elapsed) = converge_paths(&device_a, &device_b, &full_gate).await;
                for p in &touched {
                    oracle.record_round_convergence_latency(p, elapsed);
                }
                if !converged {
                    return Err(format!("seed {seed}: round {round}, paths {touched:?} never converged across both devices within the poll timeout"));
                }
                let (x, y) = if rng.random_bool(0.5) {
                    (&device_a, &device_b)
                } else {
                    (&device_b, &device_a)
                };
                let x_new_dir = format!("dir-r{round}-x");
                let y_new_dir = format!("dir-r{round}-y");
                let children: Vec<String> = siblings.iter().map(|(p, _)| basename(p)).collect();
                if debug {
                    eprintln!("  RACE(a) dual-dir-rename: old_dir={old_dir} x={}->{x_new_dir} y={}->{y_new_dir}", x.device_id, y.device_id);
                }

                deliver_local_dir_rename(x, &old_dir, &x_new_dir, &children, &clock).await?;
                tokio::time::sleep(RACE_INNER_DELAY).await;
                // `y` happens strictly after `x` within this same round: y's own
                // `fs_ops::set_mtime` call below advances the shared clock again,
                // so its stamped mtime lands strictly after x's -- no hand-tuned
                // +100ms sub-step needed (the per-mutation stamp gives the
                // ordering for free), mirroring `dst_two_device_chaos.rs`'s
                // identical drop of this nudge.

                let y_old_full = y.root.join(&old_dir);
                let y_new_full = y.root.join(&y_new_dir);
                std::fs::rename(&y_old_full, &y_new_full).map_err(|e| e.to_string())?;
                for child in &children {
                    let _ = dst_support::fs_ops::set_mtime(&clock, &y_new_full.join(child));
                }
                apply_and_push_dir_rename(y, &old_dir, &y_new_dir, &children).await?;

                for (old_path, content_id) in &siblings {
                    let base = path_baseline.get(old_path).cloned().unwrap_or_default();
                    let mut x_del = base.clone();
                    x_del.increment(&x.device_id);
                    let mut y_del = base.clone();
                    y_del.increment(&y.device_id);
                    oracle.record_delete(old_path, device_idx_of(x), x_del.clone());
                    oracle.record_delete(old_path, device_idx_of(y), y_del.clone());
                    path_baseline.insert(old_path.clone(), x_del.merge(&y_del));
                    all_files.remove(old_path);

                    let x_new_path = format!("{x_new_dir}/{}", basename(old_path));
                    let mut x_write = VersionVector::new();
                    x_write.increment(&x.device_id);
                    oracle.record_write(
                        &x_new_path,
                        device_idx_of(x),
                        *content_id,
                        x_write.clone(),
                    );
                    path_baseline.insert(x_new_path.clone(), x_write);
                    all_files.insert(x_new_path, *content_id);

                    let y_new_path = format!("{y_new_dir}/{}", basename(old_path));
                    let mut y_write = VersionVector::new();
                    y_write.increment(&y.device_id);
                    oracle.record_write(
                        &y_new_path,
                        device_idx_of(y),
                        *content_id,
                        y_write.clone(),
                    );
                    path_baseline.insert(y_new_path.clone(), y_write);
                    all_files.insert(y_new_path.clone(), *content_id);

                    // y's outcome becomes the tracked continuation
                    // (arbitrary but consistent convention -- x's
                    // independent target is still fully oracle-checked,
                    // just not reused by a later round).
                    if let Some(a) = active.iter_mut().find(|p| *p == old_path) {
                        *a = y_new_path;
                    }
                }
                tokio::time::sleep(RACE_SETTLE).await;
            }
            // Race (b) (10%): device A renames the directory while
            // device B concurrently edits one file inside it -- a direct
            // delete-vs-write race on that file's old path, plus an
            // unraced cascade for any other sibling.
            60..=69 => {
                let idx = pick_active_idx(&mut rng, &active);
                let old_dir = parent_dir(&active[idx]);
                let siblings = siblings_under(&all_files, &old_dir);
                let touched: Vec<String> = siblings.iter().map(|(p, _)| p.clone()).collect();
                // agmsg investigation fix: gate a whole-directory OS-level
                // rename on convergence of *every* path this scenario has
                // ever touched (`path_baseline`'s full key set), not just
                // `touched` (the directory's *currently modeled* children).
                // A real `std::fs::rename` moves every file physically
                // present under the directory on this specific device's
                // disk -- including a stale leftover from an *earlier*
                // round's move-away that hasn't finished materializing
                // (removing the old file / writing the new one) on this
                // device yet, even though this scenario's own model
                // already considers it relocated elsewhere. Without this,
                // that leftover gets dragged along to a name neither this
                // scenario's bookkeeping nor (transiently) either device's
                // index expects, producing a tree divergence that is a
                // harness gating gap, not a product bug (confirmed via
                // seed 3509503759: `dir-r4-y/x-0.bin` existed only on one
                // device because `newdir-r0`'s round-2 move-away of
                // `x-0.bin` to `dir-r2/x-0.bin` had not yet fully
                // materialized on that device when round 4 renamed
                // `newdir-r0` again).
                let full_gate: Vec<String> = path_baseline.keys().cloned().collect();
                let (converged, elapsed) = converge_paths(&device_a, &device_b, &full_gate).await;
                for p in &touched {
                    oracle.record_round_convergence_latency(p, elapsed);
                }
                if !converged {
                    return Err(format!("seed {seed}: round {round}, paths {touched:?} never converged across both devices within the poll timeout"));
                }
                let (x, y) = if rng.random_bool(0.5) {
                    (&device_a, &device_b)
                } else {
                    (&device_b, &device_a)
                };
                let new_dir = format!("dir-r{round}");
                let children: Vec<String> = siblings.iter().map(|(p, _)| basename(p)).collect();
                let target_path = active[idx].clone(); // y edits this specific file
                if debug {
                    eprintln!("  RACE(b) dir-rename-vs-edit-inside: old_dir={old_dir} renamer={} editor={} target={target_path}", x.device_id, y.device_id);
                }

                deliver_local_dir_rename(x, &old_dir, &new_dir, &children, &clock).await?;
                tokio::time::sleep(RACE_INNER_DELAY).await;
                // `y` happens strictly after `x` within this same round -- no
                // hand-tuned +100ms sub-step needed, same as race (a) above.

                let y_content = content_for(seed, round, &y.device_id, "race-b-edit-inside");
                let y_full = y.root.join(&target_path);
                dst_support::fs_ops::write(&clock, &y_full, &y_content)?;
                apply_and_push(y, &target_path, FsChangeKind::CreatedOrModified).await?;
                let y_content_id =
                    register_content(&mut content_table, &mut next_content_id, y_content);

                for (old_path, content_id) in &siblings {
                    let base = path_baseline.get(old_path).cloned().unwrap_or_default();
                    let is_target = *old_path == target_path;
                    if is_target {
                        let mut x_del = base.clone();
                        x_del.increment(&x.device_id);
                        let mut y_write = base.clone();
                        y_write.increment(&y.device_id);
                        oracle.record_delete(old_path, device_idx_of(x), x_del.clone());
                        oracle.record_write(
                            old_path,
                            device_idx_of(y),
                            y_content_id,
                            y_write.clone(),
                        );
                        path_baseline.insert(old_path.clone(), x_del.merge(&y_write));
                        // The target keeps its old path tracked (y's
                        // concurrent edit may keep it alive there); x's
                        // renamed-away copy of the *pre-race* content is
                        // still an independent survivor requirement below.
                        all_files.insert(old_path.clone(), y_content_id);
                    } else {
                        let mut x_del = base.clone();
                        x_del.increment(&x.device_id);
                        oracle.record_delete(old_path, device_idx_of(x), x_del.clone());
                        path_baseline.insert(old_path.clone(), x_del);
                        all_files.remove(old_path);
                    }
                    let x_new_path = format!("{new_dir}/{}", basename(old_path));
                    let mut x_write = VersionVector::new();
                    x_write.increment(&x.device_id);
                    oracle.record_write(
                        &x_new_path,
                        device_idx_of(x),
                        *content_id,
                        x_write.clone(),
                    );
                    path_baseline.insert(x_new_path.clone(), x_write);
                    all_files.insert(x_new_path.clone(), *content_id);
                    if !is_target {
                        if let Some(a) = active.iter_mut().find(|p| *p == old_path) {
                            *a = x_new_path;
                        }
                    }
                }
                tokio::time::sleep(RACE_SETTLE).await;
            }
            // Race (c) (10%): both devices create the SAME brand-new
            // directory, each with a DIFFERENT file in it -- two
            // non-contending keys, but a genuinely concurrent first
            // registration of a never-seen-before directory on both
            // sides at once.
            70..=79 => {
                let (x, y) = if rng.random_bool(0.5) {
                    (&device_a, &device_b)
                } else {
                    (&device_b, &device_a)
                };
                let new_dir = format!("newdir-r{round}");
                let x_path = format!("{new_dir}/x-{round}.bin");
                let y_path = format!("{new_dir}/y-{round}.bin");
                if debug {
                    eprintln!(
                        "  RACE(c) same-new-dir-diff-file: dir={new_dir} x={} y={}",
                        x.device_id, y.device_id
                    );
                }
                // Neither key has any prior history -- nothing to
                // converge on before this round.

                let x_content = content_for(seed, round, &x.device_id, "race-c-x");
                deliver_local_write(x, &x_path, &x_content, &clock).await?;
                tokio::time::sleep(RACE_INNER_DELAY).await;
                // `y` happens strictly after `x` within this same round -- no
                // hand-tuned +100ms sub-step needed, same as race (a) above.

                let y_content = content_for(seed, round, &y.device_id, "race-c-y");
                let y_full = y.root.join(&y_path);
                if let Some(parent) = y_full.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                dst_support::fs_ops::write(&clock, &y_full, &y_content)?;
                apply_and_push(y, &y_path, FsChangeKind::CreatedOrModified).await?;

                let x_content_id =
                    register_content(&mut content_table, &mut next_content_id, x_content);
                let y_content_id =
                    register_content(&mut content_table, &mut next_content_id, y_content);
                record_write_at(
                    &mut oracle,
                    &mut path_baseline,
                    &x_path,
                    device_idx_of(x),
                    &x.device_id,
                    x_content_id,
                );
                record_write_at(
                    &mut oracle,
                    &mut path_baseline,
                    &y_path,
                    device_idx_of(y),
                    &y.device_id,
                    y_content_id,
                );
                // Both are tracked in `all_files` (so a later directory
                // rename over `new_dir` correctly discovers both -- see
                // `pick_active_idx`'s doc comment); only y's file becomes
                // a fresh active target, x's is an independent survivor
                // requirement, not reused later.
                all_files.insert(x_path, x_content_id);
                all_files.insert(y_path.clone(), y_content_id);
                active.push(y_path);
                tokio::time::sleep(RACE_SETTLE).await;
            }
            // Race (d) (10%): device A moves a file out of its directory
            // while device B concurrently edits it -- delete-vs-
            // write on the old path, plus an independent write at the
            // move's destination.
            80..=89 => {
                let idx = pick_active_idx(&mut rng, &active);
                let old_path = active[idx].clone();
                let (converged, elapsed) =
                    converge_paths(&device_a, &device_b, &[old_path.clone()]).await;
                oracle.record_round_convergence_latency(&old_path, elapsed);
                if !converged {
                    return Err(format!("seed {seed}: round {round}, path {old_path} never converged across both devices within the poll timeout"));
                }
                let content_id = all_files[&old_path];
                let (x, y) = if rng.random_bool(0.5) {
                    (&device_a, &device_b)
                } else {
                    (&device_b, &device_a)
                };
                let dest_dir = format!("moved-r{round}");
                let new_path = format!("{dest_dir}/{}", basename(&old_path));
                if debug {
                    eprintln!("  RACE(d) move-out-vs-edit: old={old_path} new={new_path} mover={} editor={}", x.device_id, y.device_id);
                }

                // Precondition for the physical move: the mover can only
                // `std::fs::rename` a file that is actually on its disk. If a
                // prior round already removed old_path from x's disk (e.g. a
                // delete-vs-write tombstone whose surviving edit lives on as a
                // conflict copy), issuing the OS rename would ENOENT -- skip
                // this race round instead of driving an impossible op. With
                // the bookkeeping below (old_path is never left in
                // `active`/`all_files` as a live file), old_path is a genuine
                // converged live file here, so this is a guard, not the
                // common path.
                if !x.root.join(&old_path).exists() {
                    if debug {
                        eprintln!(
                            "  RACE(d) skipped: {old_path} absent on mover {} -- avoiding ENOENT",
                            x.device_id
                        );
                    }
                    tokio::time::sleep(RACE_SETTLE).await;
                    continue;
                }

                deliver_local_rename(x, &old_path, &new_path, &clock).await?;
                tokio::time::sleep(RACE_INNER_DELAY).await;
                // `y` happens strictly after `x` within this same round -- no
                // hand-tuned +100ms sub-step needed, same as race (a) above.

                let y_content = content_for(seed, round, &y.device_id, "race-d-edit");
                let y_full = y.root.join(&old_path);
                dst_support::fs_ops::write(&clock, &y_full, &y_content)?;
                apply_and_push(y, &old_path, FsChangeKind::CreatedOrModified).await?;
                let y_content_id =
                    register_content(&mut content_table, &mut next_content_id, y_content);

                let base = path_baseline.get(&old_path).cloned().unwrap_or_default();
                let mut x_del = base.clone();
                x_del.increment(&x.device_id);
                let mut y_write = base.clone();
                y_write.increment(&y.device_id);
                oracle.record_delete(&old_path, device_idx_of(x), x_del.clone());
                oracle.record_write(&old_path, device_idx_of(y), y_content_id, y_write.clone());
                path_baseline.insert(old_path.clone(), x_del.merge(&y_write));

                let mut x_write = VersionVector::new();
                x_write.increment(&x.device_id);
                oracle.record_write(&new_path, device_idx_of(x), content_id, x_write.clone());
                path_baseline.insert(new_path.clone(), x_write);
                all_files.insert(new_path.clone(), content_id);

                // old_path is a delete-vs-write tombstone: the mover removed
                // it and the product preserves y's concurrent edit as a
                // conflict copy under some (possibly rename-relocated) name.
                // That survivor is a survives-anywhere conflict copy, NOT a
                // stable live file at old_path -- the oracle's whole-tree
                // no-loss search already accounts for it via the
                // `record_write(&old_path, y,...)` above. Do NOT keep
                // old_path in `all_files`/`active` as a live on-disk file: a
                // later whole-directory rename must never try to physically
                // move a file the product already deleted (that path ENOENTs).
                // The live continuation at this location is now new_path.
                all_files.remove(&old_path);
                active[idx] = new_path;
                tokio::time::sleep(RACE_SETTLE).await;
            }
            // Race (e) (10%): rename-vs-delete of the same path -- device
            // X renames it away (pending), device Y deletes the same old
            // path outright (applied). Both concurrent deletes of the old
            // key; X's new-path write is an independent survivor.
            _ => {
                let idx = pick_active_idx(&mut rng, &active);
                let old_path = active[idx].clone();
                let (converged, elapsed) =
                    converge_paths(&device_a, &device_b, &[old_path.clone()]).await;
                oracle.record_round_convergence_latency(&old_path, elapsed);
                if !converged {
                    return Err(format!("seed {seed}: round {round}, path {old_path} never converged across both devices within the poll timeout"));
                }
                let content_id = all_files[&old_path];
                let (x, y) = if rng.random_bool(0.5) {
                    (&device_a, &device_b)
                } else {
                    (&device_b, &device_a)
                };
                let dir = parent_dir(&old_path);
                let new_path = if dir.is_empty() {
                    format!("renamed-e-r{round}.bin")
                } else {
                    format!("{dir}/renamed-e-r{round}.bin")
                };
                if debug {
                    eprintln!("  RACE(e) rename-vs-delete: old={old_path} new={new_path} renamer={} deleter={}", x.device_id, y.device_id);
                }

                deliver_local_rename(x, &old_path, &new_path, &clock).await?;
                tokio::time::sleep(RACE_INNER_DELAY).await;
                // `y` happens strictly after `x` within this same round -- no
                // hand-tuned +100ms sub-step needed, same as race (a) above.

                dst_support::fs_ops::remove(&y.root.join(&old_path))?;
                apply_and_push(y, &old_path, FsChangeKind::Removed).await?;

                let base = path_baseline.get(&old_path).cloned().unwrap_or_default();
                let mut x_del = base.clone();
                x_del.increment(&x.device_id);
                let mut y_del = base.clone();
                y_del.increment(&y.device_id);
                oracle.record_delete(&old_path, device_idx_of(x), x_del.clone());
                oracle.record_delete(&old_path, device_idx_of(y), y_del.clone());
                path_baseline.insert(old_path.clone(), x_del.merge(&y_del));
                all_files.remove(&old_path);

                let mut x_write = VersionVector::new();
                x_write.increment(&x.device_id);
                oracle.record_write(&new_path, device_idx_of(x), content_id, x_write.clone());
                path_baseline.insert(new_path.clone(), x_write);
                all_files.insert(new_path.clone(), content_id);

                // x's renamed-away copy becomes the tracked continuation
                // (the old key is gone on both sides -- nothing left to
                // track there).
                active[idx] = new_path;
                tokio::time::sleep(RACE_SETTLE).await;
            }
        }
    }

    let devices: Vec<(&Path, &SyncState)> = vec![
        (device_a.root.as_path(), device_a.state.as_ref()),
        (device_b.root.as_path(), device_b.state.as_ref()),
    ];

    // agmsg investigation, 2026-07-09 (Class-2 harness-fidelity vs.
    // genuine-risk decisive test): mirror `dst_two_device_chaos.rs`'s F.2
    // recovery-at-quiescence, but for the directory-registrar case rather
    // than the interrupted-materialize one. A real daemon watches every
    // directory with `notify` and, every time a directory newly appears
    // (including one produced by a rename's destination), runs
    // `watcher.rs::reconcile_new_directory_subtree` -- a `walkdir` of that
    // directory's *actual on-disk contents* that synthesizes a
    // `CreatedOrModified` for every real file it finds, so a file that
    // physically exists on disk but was never reported by a live watcher
    // event still gets indexed and propagated. The same design also runs
    // `LocalChangeProcessor::reconcile_added_files` (the "add-disk-
    // reconcile-backstop" periodic sweep) as a second, standalone backstop
    // for exactly this: index any on-disk file that has no index row --
    // "byte-for-byte what a live create event would have done" (see that
    // method's own doc comment), the add-only, mid-conflict-safe scope.
    // This bare-`PeerSyncSession` harness's simulated event delivery
    // replicates neither, so a file dragged to a new path by a real
    // `std::fs::rename` of its parent directory (Class 2's stray) is never
    // re-scanned. Run `reconcile_added_files` here, once per device at
    // quiescence, and push whatever it newly indexes to the peer the same
    // way a live create would -- if the divergence then heals, Class 2 is
    // a harness-fidelity gap (production self-heals via this exact
    // recovery); if it persists, it is a genuine product risk the recovery
    // does not cover even when invoked.
    for device in [&device_a, &device_b] {
        if let Ok(records) = device.processor.reconcile_added_files(GROUP_ID, &device.root) {
            if !records.is_empty() {
                if debug {
                    for r in &records {
                        eprintln!(
                            "  [{}] QUIESCENCE reconcile_added_files -> re-index+announce: path={:?} deleted={}",
                            device.device_id, r.path, r.deleted
                        );
                    }
                }
                if let Some(session) = device.session.get() {
                    // `reconcile_added_files` appended a signed change per newly
                    // indexed file; announce heads so the peer pulls them.
                    let _ = session.announce_local_commit(GROUP_ID).await;
                }
            }
        }
    }

    // Gap B: the shared `settle` primitive polls `check_convergence_recursive`
    // on the sim clock and returns the instant it converges. On budget
    // exhaustion it records a non-fatal `SlowConvergence`
    // instead of the old hand-rolled poll loop's hard timeout -- the terminal
    // `check_convergence_recursive` below still hard-fails on a genuinely
    // divergent final state.
    let outcome =
        dst_support::settle::settle_recursive(&devices, &oracle, FINAL_CONVERGENCE_BUDGET).await;
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
    // called either, so an interrupted eager materialize's window left a
    // live-but-fileless index row + an orphaned `.yadorilink-tmp.*` file
    // permanently, surfacing as `StructuralIndexDiskMismatch`/`Corruption`
    // violations the same production self-healing sweep would have already
    // cleared (see `dst_two_device_chaos.rs`'s identical account, seed
    // 3298840595's finding). Run once per device at this scenario's own
    // genuinely-quiescent point via the shared `dst_support::sweep`
    // primitive (Gap C), matching daemon fidelity, not masking the
    // underlying materialize-ordering gap.
    for (device, store) in [(&device_a, &recovery_store_a), (&device_b, &recovery_store_b)] {
        for finding in dst_support::sweep::run_self_healing(
            &device.state,
            store.as_ref(),
            &device.root,
            GROUP_ID,
        ) {
            eprintln!("  {finding}");
        }
    }

    if debug {
        for (root, _) in &devices {
            fn list_recursive(dir: &Path, root: &Path, out: &mut Vec<String>) {
                let Ok(entries) = std::fs::read_dir(dir) else { return };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        list_recursive(&path, root, out);
                    } else if let Ok(rel) = path.strip_prefix(root) {
                        out.push(rel.to_string_lossy().to_string());
                    }
                }
            }
            let mut entries = Vec::new();
            list_recursive(root, root, &mut entries);
            eprintln!("  final tree on {}: {entries:?}", root.display());
        }
        for (id, bytes) in content_table.iter() {
            eprintln!("  content_id {id}: {:?}", String::from_utf8_lossy(bytes));
        }
    }

    let mut violations = Vec::new();
    // No separate hard "did not converge in budget" violation --
    // `settle_recursive` above already recorded a non-fatal `SlowConvergence`
    // if the budget was exhausted, and this terminal `check_convergence_
    // recursive` hard-fails here if (and only if) the final state is
    // genuinely divergent rather than merely slow. `converged` remains only
    // for the debug print above.
    let _ = converged;
    violations.extend(oracle.check_convergence_recursive(&devices));
    violations.extend(oracle.check_no_loss_recursive(&content_table, &devices));
    violations.extend(oracle.check_conflict_copy_accounting_recursive(
        &content_table,
        &devices,
        GROUP_ID,
    ));
    violations.extend(oracle.check_no_corruption_recursive(&content_table, &devices));
    violations.extend(oracle.check_structural(GROUP_ID, &devices));

    for slow in oracle.check_convergence_promptness(CONVERGENCE_PROMPTNESS_SLA) {
        eprintln!("  PROMPTNESS: {slow}");
    }

    if debug {
        for v in &violations {
            eprintln!("  VIOLATION: {v}");
        }
    }
    if !violations.is_empty() {
        return Err(dst_support::oracle::format_violations(seed, &violations));
    }
    Ok(())
}

fn run_in_madsim(seed: u64, ops_per_run: usize) -> Result<(), String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    rt.set_time_limit(Duration::from_secs(100));
    rt.block_on(run_scenario(seed, ops_per_run)).map_err(|e| {
        if e.starts_with(BASELINE_TIMEOUT_MARKER) || e.contains(&format!("seed {seed}")) {
            e
        } else {
            format!("seed {seed}: {e}")
        }
    })
}

/// Same rationale as `dst_two_device_chaos.rs`'s identical marker: a
/// genuine WireGuard-handshake-under-simulated-time livelock, not a
/// deadlock in this scenario's own logic.
const TIME_LIMIT_MARKER: &str = "TIME_LIMIT: ";
/// Same rationale as `dst_two_device_chaos.rs`'s identical marker: OS
/// thread-creation ceiling from r2d2's per-`SyncState` background thread
/// across many sequential seeds in one process.
const RESOURCE_EXHAUSTION_MARKER: &str = "RESOURCE_EXHAUSTION: ";

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

/// This file's one network-touching `#[test]` fn, same reasoning as
/// `dst_two_device_chaos.rs`'s identical constraint (madsim's simulated
/// network state isn't safe across more than one network-touching
/// `#[test]` fn per binary).
#[test]
fn directory_chaos_scenario() {
    let variations: u64 = std::env::var("DST_VARIATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_VARIATIONS);
    let ops_per_run: usize = std::env::var("DST_CHAOS_OPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_OPS_PER_RUN);
    let base_seed: u64 =
        std::env::var("DST_BASE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0xD12E_C700);

    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let mut skipped_baseline = 0;
    let mut skipped_time_limit = 0;
    let mut skipped_resource_exhaustion = 0;
    let mut failures = Vec::new();

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
        "{}/{variations} directory chaos variations found an oracle violation (skipped \
         {skipped_baseline} on baseline timeout, {skipped_time_limit} on the madsim time limit, \
         {skipped_resource_exhaustion} on OS thread-creation exhaustion):\n{}\n\
         (reproduce one with DST_BASE_SEED=<seed> DST_VARIATIONS=1 DST_DIR_CHAOS_DEBUG=1 cargo \
         test ... directory_chaos_scenario, then narrow to run_scenario(seed, ops) directly)",
        failures.len(),
        failures.join("\n---\n")
    );
    assert!(
        skipped < variations,
        "every seed hit BASELINE_TIMEOUT -- nothing was actually exercised"
    );
}
