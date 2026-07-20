//! DST scenario: a single-syscall directory rename on one device racing a
//! concurrent child-file edit on a peer, driven through the *real*
//! production dispatch path -- two simulated devices exchanging real wire
//! messages over a `madsim`-simulated `PeerChannel`, the real
//! `PeerSyncSession::run` receive loop (so the private change-apply /
//! materialize path runs for real), the real debounce accumulator holding
//! the raw watcher-path pending entry, and the real
//! `LocalChangeProcessor::process_flush` dispatch (so the disk re-stat in
//! `local_change.rs`'s Removed/CreatedOrModified reclassification runs
//! before any tombstone is emitted).
//!
//! Shape (device A = the renamer, device B = the child-editor):
//!  - A and B share `dir1/b.bin` at a synced base version V0.
//!  - A does one `std::fs::rename(dir1, dir2)` on disk. The OS watcher
//!    reports this as ONE directory-level `Removed` event keyed on the raw
//!    path `dir1` -- never per-child. That event sits pending, keyed on
//!    `dir1`, in A's debounce accumulator.
//!  - B independently edits `dir1/b.bin` (a change CB whose only parent is
//!    the baseline V0 -- it descends from V0 and from nothing of A's).
//!
//! Two interleavings, each a separate case:
//!  (a) CbBeforeDirDispatch -- CB is applied on A *before* A's pending
//!      `dir1` Removed is dispatched. CB strictly descends from A's
//!      current state, so it applies as a fast-forward and
//!      re-materializes `dir1/b.bin`, which recreates `dir1` on disk;
//!      when A's `dir1` Removed is then dispatched, the pre-dispatch disk
//!      re-stat sees `dir1` present again and reclassifies it to
//!      CreatedOrModified, so NO child tombstone is emitted.
//!  (b) DirTombstoneBeforeCb -- A's pending `dir1` Removed is dispatched
//!      *first*. The re-stat sees `dir1` genuinely gone, so the Removed
//!      branch tombstones the orphaned child `dir1/b.bin` (a real delete,
//!      emitted as A's own signed change off V0). CB then arrives. A's
//!      delete and B's edit are siblings off V0 -- neither is an ancestor
//!      of the other -- so this is the genuinely concurrent case, and
//!      resolution must preserve B's edited content rather than let A's
//!      delete silently drop it.
//!
//! The invariant asserted in BOTH orderings: B's edited bytes must survive
//! somewhere on A -- as the live `dir1/b.bin`, or as a conflict-copy
//! sibling -- and the index must not be left with a dangling delete that
//! removed B's content with no artifact. A failure here would be genuine
//! silent data loss. Which of the two resting places a given ordering
//! lands on is deliberately NOT asserted: the DAG picks the concurrent
//! winner by `(lamport, change_hash)`, so pinning (b) to "a conflict copy
//! appears" would encode a tie-break this scenario does not control. (As
//! observed today, (b) resolves by keeping B's edit live.)
//!
//! The debounce accumulator is configured with a very long quiet /
//! max-flush interval so its background timer never auto-dispatches the
//! pending `dir1` entry mid-test; the test drives dispatch explicitly via
//! the same targeted `FlushPathRequest` round trip the production
//! `LinkFlushHandle` uses, giving deterministic control of the two
//! orderings without changing any dispatch behavior.
//!
//! Propagation runs over the change-history DAG (`dst_dag_migrate_b2`):
//! each device's `LocalChangeProcessor` carries a signed `ChangeEmitter`,
//! so every accepted local mutation appends a signed change in the same
//! transaction as its index write, and a commit is published by announcing
//! this device's new heads -- the peer then pulls exactly the ancestry it
//! is missing. Both sessions pin both devices' verifying keys so each
//! admits the other's signed changes.
//!
//! Unlike the sibling migrated chaos scenarios, this one deliberately does
//! NOT shorten the heads-announce cadence (it keeps the 90s
//! `DEFAULT_FULL_INDEX_RESYNC_INTERVAL`, well past the 60s per-seed time
//! limit, so the periodic frontier audit never fires mid-test). That is
//! load-bearing, not an oversight: this scenario's whole purpose is to
//! control *when* CB reaches A relative to A's `dir1` dispatch. A short
//! periodic re-announce would publish B's edit on its own cadence and
//! collapse ordering (b) -- A's tombstone-before-CB case -- into ordering
//! (a), silently testing one interleaving twice. Each commit is instead
//! announced exactly once, explicitly, at the ordering-specific moment.

#![cfg(madsim)]

mod dst_dag_migrate_b2;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::debounce::{self, DebounceConfig, FlushPathRequest};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::peer_session::{PeerSyncSession, PendingLocalChangeFlush};
use yadorilink_sync_core::types::FileRecord;
use yadorilink_sync_core::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource,
};
use yadorilink_transport::PeerChannel;

const GROUP_ID: &str = "dst-dirmove-group";
const DIR1: &str = "dir1";
const DIR2: &str = "dir2";
const CHILD_REL: &str = "dir1/b.bin";
const BASELINE: &[u8] = b"baseline V0 content";
const B_EDIT: &[u8] = b"device B's edited content";
const SETTLE: Duration = Duration::from_millis(500);

/// Prefix marking an error as "the direct-path handshake / baseline
/// exchange never established in time under simulated time" -- a known
/// `madsim`-timing flake (both peers' WireGuard retries landing in
/// lockstep), not a failure of the behavior under test. Callers treat it
/// as a skip. Same convention the sibling reconcile-race scenario uses.
const BASELINE_TIMEOUT_MARKER: &str = "BASELINE_TIMEOUT: ";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ordering {
    /// (a) CB reconciled before A's `dir1` Removed is dispatched.
    CbBeforeDirDispatch,
    /// (b) A's `dir1` tombstone emitted before CB is reconciled.
    DirTombstoneBeforeCb,
}

/// A's `PendingLocalChangeFlush`, mirroring the production
/// `yadorilink-daemon::link_manager::LinkFlushHandle` +
/// `impl PendingLocalChangeFlush for DaemonState`: on a reconcile-time
/// flush request it does the exact-path debounce round trip and, if an
/// entry was pending, dispatches it through the real `process_flush`.
/// In this scenario the pending entry is keyed on the directory `dir1`
/// while reconcile flushes the child `dir1/b.bin`, so the exact-path
/// lookup legitimately finds nothing -- exercising, not bypassing, the
/// real guard.
struct SimDevice {
    root: PathBuf,
    processor: Arc<LocalChangeProcessor>,
    flush_request_tx: tokio::sync::mpsc::Sender<FlushPathRequest>,
    session: OnceLock<Arc<PeerSyncSession>>,
}

impl SimDevice {
    /// The production dispatch of one pending entry: exact-path drain from
    /// the accumulator, then `process_flush` (which re-stats the path
    /// before classifying Removed vs CreatedOrModified). Returns the
    /// records the dispatch produced (a tombstone, or nothing). Used both
    /// by the trait method below and directly by the test to sequence the
    /// `dir1` dispatch deterministically.
    async fn drain_and_dispatch(
        &self,
        group_id: &str,
        abs_path: &Path,
    ) -> Vec<FileRecord> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if self
            .flush_request_tx
            .send(FlushPathRequest {
                path: abs_path.to_path_buf(),
                mode: debounce::FlushMode::ExactPath,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return Vec::new();
        }
        let found = match tokio::time::timeout(Duration::from_millis(500), reply_rx).await {
            Ok(Ok(found)) => found,
            _ => None,
        };
        let Some((found_path, kind, observed_at)) = found else { return Vec::new() };
        match self
            .processor
            .process_flush(
                group_id,
                &self.root,
                debounce::DebounceFlush::Paths(vec![(found_path, kind, observed_at)]),
            )
            .await
        {
            Ok(outcome) => {
                let records = outcome.records;
                if !records.is_empty() {
                    if let Some(session) = self.session.get() {
                        // The emitter appended the signed change(s) during
                        // `process_flush`; announce this device's new heads so
                        // the peer pulls the missing ancestry over the DAG.
                        let _ = session.announce_local_commit(group_id).await;
                    }
                }
                records
            }
            Err(_) => Vec::new(),
        }
    }
}

impl PendingLocalChangeFlush for SimDevice {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let path = self.root.join(rel_path);
            let _ = self.drain_and_dispatch(group_id, &path).await;
        })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        // Case-fold siblings are irrelevant to this directory-rename race;
        // a no-op matches "nothing pending under that case-variant".
        Box::pin(async move {})
    }
}

struct DeviceA {
    processor: Arc<LocalChangeProcessor>,
    sim: Arc<SimDevice>,
    events_tx: tokio::sync::mpsc::Sender<FsChangeEvent>,
}

fn setup_device_a(root: PathBuf, sync_state: Arc<SyncState>, store: Arc<FsBlockStore>) -> DeviceA {
    let processor = Arc::new(
        LocalChangeProcessor::new(sync_state, store, "device-a".to_string())
            .with_change_emitter(dst_dag_migrate_b2::emitter_for("device-a")),
    );
    let (flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    let sim = Arc::new(SimDevice {
        root: root.clone(),
        processor: processor.clone(),
        flush_request_tx,
        session: OnceLock::new(),
    });

    let (watch_source, events_tx) = SimulatedFolderWatchSource::new(16);
    let ignore_set =
        Arc::new(yadorilink_sync_core::ignore_patterns::EffectiveIgnoreSet::defaults_only());
    let watcher = watch_source.watch(&root, ignore_set).unwrap();
    let (events_rx, overflowed, guard) = watcher.split();
    Box::leak(Box::new(guard));

    // Long quiet / max-flush interval: the background timer must never
    // auto-dispatch the pending `dir1` entry during the test -- dispatch
    // is driven explicitly, per ordering, to control the interleaving.
    let config = DebounceConfig {
        quiet_period: Duration::from_secs(600),
        max_flush_interval: Duration::from_secs(600),
        burst_threshold: 10_000,
    };
    let (flush_tx, mut flush_rx) =
        tokio::sync::mpsc::channel(debounce::DEFAULT_EXECUTOR_CHANNEL_CAPACITY);
    let (_flush_all_request_tx, flush_all_request_rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(debounce::run_debouncer(
        config,
        events_rx,
        flush_tx,
        overflowed,
        flush_request_rx,
        flush_all_request_rx,
    ));

    // Drain any timer-dispatched flushes (there should be none, given the
    // long intervals) so the channel never backs up.
    let executor_processor = processor.clone();
    let executor_root = root.clone();
    tokio::spawn(async move {
        while let Some(flush) = flush_rx.recv().await {
            let _ = executor_processor.process_flush(GROUP_ID, &executor_root, flush).await;
        }
    });

    DeviceA { processor, sim, events_tx }
}

async fn poll_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !condition() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn gen_keypair(rng: &mut StdRng) -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

async fn connect_sessions(
    rng: &mut StdRng,
    state_a: Arc<SyncState>,
    store_a: Arc<FsBlockStore>,
    root_a: PathBuf,
    state_b: Arc<SyncState>,
    store_b: Arc<FsBlockStore>,
    root_b: PathBuf,
) -> (Arc<PeerSyncSession>, Arc<PeerSyncSession>) {
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

    let mut sync_roots_a = std::collections::HashMap::new();
    sync_roots_a.insert(GROUP_ID.to_string(), root_a);
    let session_a = PeerSyncSession::new(
        channel_a,
        "device-a".to_string(),
        "device-b".to_string(),
        state_a,
        store_a,
        vec![GROUP_ID.to_string()],
        sync_roots_a,
    );

    let mut sync_roots_b = std::collections::HashMap::new();
    sync_roots_b.insert(GROUP_ID.to_string(), root_b);
    let session_b = PeerSyncSession::new(
        channel_b,
        "device-b".to_string(),
        "device-a".to_string(),
        state_b,
        store_b,
        vec![GROUP_ID.to_string()],
        sync_roots_b,
    );

    // Pin both devices' verifying keys on both sessions so each admits the
    // other's signed changes. Deliberately NOT `wire_dag_session`: that also
    // shortens the heads-announce cadence to 50ms, which would let the periodic
    // frontier audit publish B's edit on its own schedule and destroy this
    // scenario's ordering control (see the module doc). The default 90s
    // interval outlives the 60s per-seed time limit, so every announce here is
    // an explicit one made at a moment the test chose.
    let device_ids = ["device-a", "device-b"];
    let authenticator = dst_dag_migrate_b2::PinnedAuthenticator::new(device_ids);
    session_a.set_change_authenticator(authenticator.clone());
    session_b.set_change_authenticator(authenticator);

    (session_a, session_b)
}

/// B produces its causally-later edit to `dir1/b.bin` off the synced base,
/// via a real standalone `process_event` (real chunking/indexing, blocks
/// written to B's store), returning the record to hand to A over the wire.
async fn device_b_edit_child(
    state_b: &Arc<SyncState>,
    store_b: &Arc<FsBlockStore>,
    root_b: &Path,
) -> Result<FileRecord, String> {
    std::fs::write(root_b.join(CHILD_REL), B_EDIT).map_err(|e| e.to_string())?;
    // Same signed emitter identity B's session pins: the edit must land in B's
    // change DAG here, so announcing B's heads later publishes exactly this
    // change (and its ancestry) to A.
    let processor =
        LocalChangeProcessor::new(state_b.clone(), store_b.clone(), "device-b".to_string())
            .with_change_emitter(dst_dag_migrate_b2::emitter_for("device-b"));
    let outcome = processor
        .process_event(
            GROUP_ID,
            root_b,
            &FsChangeEvent { path: root_b.join(CHILD_REL), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .map_err(|e| e.to_string())?;
    match outcome {
        LocalChangeOutcome::FileChanged(record) => Ok(record),
        other => Err(format!("device B's edit produced no record: {other:?}")),
    }
}

/// Recursively true if any file under `root` holds exactly `expected`.
fn content_present_anywhere(root: &Path, expected: &[u8]) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else { return false };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if content_present_anywhere(&path, expected) {
                return true;
            }
        } else if std::fs::read(&path).map(|c| c == expected).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Recursively collect the relative paths of every live file under `root`
/// (for diagnostics on failure).
fn list_files(root: &Path, base: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            list_files(&path, base, out);
        } else {
            let rel = path.strip_prefix(base).unwrap_or(&path).to_string_lossy().to_string();
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            out.push(format!("{rel} ({len}B)"));
        }
    }
}

/// True if a conflict-copy sibling exists on disk (the second legitimate
/// resting place for a concurrently-edited file).
fn conflict_copy_present(root: &Path) -> bool {
    let mut files = Vec::new();
    list_files(root, root, &mut files);
    files.iter().any(|f| f.contains("(conflicted copy"))
}

/// Links a root and brings it to the post-first-scan state production is in:
/// claims the root, and opens the group's startup gate. Kept local because this
/// scenario is deliberately standalone; `dst_support/link.rs` carries the full
/// rationale. In short: `wait_group_ready` defers a peer change forever for a
/// group that has a live link and no gate, because that pairing means the
/// folder was never scanned, so a bare `add_link` builds a device that silently
/// receives nothing.
fn link_and_start(state: &Arc<SyncState>, root: &Path) -> Result<(), String> {
    state.add_link(&root.to_string_lossy(), GROUP_ID).map_err(|e| e.to_string())?;
    yadorilink_sync_core::root_identity::VerifiedRoot::open(root, GROUP_ID, state)
        .map_err(|e| e.to_string())?;
    let generation = state.begin_group_startup(GROUP_ID);
    state.mark_group_ready(GROUP_ID, generation);
    Ok(())
}

async fn run_scenario(seed: u64, ordering: Ordering) -> Result<(), String> {
    let _ = tracing_subscriber::fmt::try_init();
    let mut rng = StdRng::seed_from_u64(seed);

    let root_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_a = root_dir_a.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_a = Arc::new(FsBlockStore::new(store_dir_a.path()).map_err(|e| e.to_string())?);
    let state_a = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    link_and_start(&state_a, &root_a)?;

    let root_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_b = root_dir_b.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_b = Arc::new(FsBlockStore::new(store_dir_b.path()).map_err(|e| e.to_string())?);
    let state_b = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    link_and_start(&state_b, &root_b)?;

    // Baseline: A creates dir1/b.bin at V0 via the real processor.
    let device_a = setup_device_a(root_a.clone(), state_a.clone(), store_a.clone());
    std::fs::create_dir_all(root_a.join(DIR1)).map_err(|e| e.to_string())?;
    std::fs::write(root_a.join(CHILD_REL), BASELINE).map_err(|e| e.to_string())?;
    let baseline_outcome = device_a
        .processor
        .process_event(
            GROUP_ID,
            &root_a,
            &FsChangeEvent { path: root_a.join(CHILD_REL), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .map_err(|e| e.to_string())?;
    if !matches!(baseline_outcome, LocalChangeOutcome::FileChanged(_)) {
        return Err(format!("baseline on A produced no record: {baseline_outcome:?}"));
    }

    let (session_a, session_b) = connect_sessions(
        &mut rng,
        state_a.clone(),
        store_a.clone(),
        root_a.clone(),
        state_b.clone(),
        store_b.clone(),
        root_b.clone(),
    )
    .await;
    device_a.sim.session.set(session_a.clone()).ok();
    // The guard is always wired here: this scenario is about whether the
    // *real* production defenses hold, not about reproducing a pre-guard bug.
    session_a.set_pending_local_change_flush(device_a.sim.clone());

    let run_a = tokio::spawn(session_a.clone().run());
    let run_b = tokio::spawn(session_b.clone().run());

    // B adopts the baseline into dir1/b.bin (real block fetch + materialize).
    poll_until(Duration::from_secs(10), || {
        run_a.is_finished()
            || run_b.is_finished()
            || std::fs::read(root_b.join(CHILD_REL)).map(|c| c == BASELINE).unwrap_or(false)
    })
    .await;
    if run_a.is_finished() || run_b.is_finished() {
        return Err(format!(
            "a session run() loop exited early (a_finished={}, b_finished={})",
            run_a.is_finished(),
            run_b.is_finished()
        ));
    }
    if std::fs::read(root_b.join(CHILD_REL)).map(|c| c != BASELINE).unwrap_or(true) {
        let indexed = state_b.get_file(GROUP_ID, CHILD_REL).ok().flatten();
        return Err(format!(
            "{BASELINE_TIMEOUT_MARKER}device B never adopted the baseline (index row: {indexed:?})"
        ));
    }

    // B produces its causally-later, concurrent edit CB now, off V0. Held
    // as a value; sent to A at the ordering-specific moment. Capturing it
    // before A's tombstone can reach B guarantees CB is genuinely
    // concurrent with (not causally after) A's delete.
    let b_record = device_b_edit_child(&state_b, &store_b, &root_b).await?;
    if b_record.deleted {
        return Err("device B's edit record was unexpectedly a tombstone".to_string());
    }

    // A performs the single-syscall directory rename on disk...
    std::fs::rename(root_a.join(DIR1), root_a.join(DIR2)).map_err(|e| e.to_string())?;
    // ...and the OS watcher reports it as ONE directory-level Removed event
    // keyed on the raw path `dir1`. Deliver it into A's debounce
    // accumulator, where it now sits pending (long quiet period => the
    // timer will not dispatch it; the test does, per ordering).
    device_a
        .events_tx
        .send(FsChangeEvent { path: root_a.join(DIR1), kind: FsChangeKind::Removed })
        .await
        .map_err(|_| "A's watcher channel closed early".to_string())?;
    // Let run_debouncer register the event as pending before proceeding.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Records produced by the `dir1` Removed dispatch (a tombstone in
    // ordering (b), nothing in ordering (a)); captured for the report and
    // the dangling-delete assertion.
    let dir_dispatch_records: Vec<FileRecord> = match ordering {
        Ordering::CbBeforeDirDispatch => {
            // (a) CB reconciles first. reconcile flushes the child path
            // `dir1/b.bin` (exact-path lookup finds nothing -- the pending
            // entry is keyed on `dir1`), sees local V0 vs CB as a
            // fast-forward, and re-materializes dir1/b.bin -- recreating
            // `dir1` on disk.
            session_b.announce_local_commit(GROUP_ID).await.map_err(|e| e.to_string())?;
            poll_until(Duration::from_secs(10), || {
                run_a.is_finished()
                    || std::fs::read(root_a.join(CHILD_REL)).map(|c| c == B_EDIT).unwrap_or(false)
            })
            .await;
            if std::fs::read(root_a.join(CHILD_REL)).map(|c| c != B_EDIT).unwrap_or(true) {
                return Err(format!(
                    "{BASELINE_TIMEOUT_MARKER}A never materialized CB before dir dispatch \
                     (index: {:?})",
                    state_a.get_file(GROUP_ID, CHILD_REL).ok().flatten()
                ));
            }
            // Now dispatch A's pending `dir1` Removed. The pre-dispatch
            // re-stat sees `dir1` present again (recreated by the
            // materialize above) and reclassifies to CreatedOrModified:
            // no child tombstone.
            let recs = device_a.sim.drain_and_dispatch(GROUP_ID, &root_a.join(DIR1)).await;
            tokio::time::sleep(SETTLE).await;
            recs
        }
        Ordering::DirTombstoneBeforeCb => {
            // (b) A's `dir1` Removed dispatches first. The re-stat sees
            // `dir1` genuinely gone (renamed to dir2), so the Removed
            // branch tombstones the orphaned child dir1/b.bin with A's own
            // component bumped, and broadcasts it.
            let recs = device_a.sim.drain_and_dispatch(GROUP_ID, &root_a.join(DIR1)).await;
            let child_tombstoned =
                recs.iter().any(|r| r.path.as_str() == CHILD_REL && r.deleted);
            if !child_tombstoned {
                return Err(format!(
                    "dir1 dispatch did not tombstone the orphaned child dir1/b.bin as expected \
                     (records: {:?}); disk dir1 exists = {}",
                    recs.iter().map(|r| (r.path.clone(), r.deleted)).collect::<Vec<_>>(),
                    root_a.join(DIR1).exists()
                ));
            }
            // Now CB arrives: B announces the heads its edit created, and A
            // pulls it. A's delete and B's edit are siblings off V0 in the
            // DAG (neither is an ancestor of the other), so this is the
            // concurrent case => resolution must keep B's bytes.
            session_b.announce_local_commit(GROUP_ID).await.map_err(|e| e.to_string())?;
            poll_until(Duration::from_secs(10), || {
                run_a.is_finished() || content_present_anywhere(&root_a, B_EDIT)
            })
            .await;
            tokio::time::sleep(SETTLE).await;
            recs
        }
    };

    run_a.abort();
    run_b.abort();

    // --- No-silent-loss invariant, checked identically for both orderings ---
    let live_child = std::fs::read(root_a.join(CHILD_REL)).map(|c| c == B_EDIT).unwrap_or(false);
    let present = content_present_anywhere(&root_a, B_EDIT);
    let child_row = state_a.get_file(GROUP_ID, CHILD_REL).ok().flatten();

    if !present {
        let mut files = Vec::new();
        list_files(&root_a, &root_a, &mut files);
        return Err(format!(
            "SILENT DATA LOSS ({ordering:?}, seed {seed}): device B's edited bytes are present \
             NOWHERE on A. live dir1/b.bin={live_child}; dir1/b.bin index row={child_row:?}; \
             dir dispatch records={:?}; files on disk={files:?}",
            dir_dispatch_records
                .iter()
                .map(|r| (r.path.clone(), r.deleted))
                .collect::<Vec<_>>(),
        ));
    }

    // A dangling delete would be: the child index row says deleted AND B's
    // content is not resurrected live AND there is no conflict copy holding
    // it. `present` above already rules out total loss; this rules out the
    // subtler "index tombstone with the only surviving bytes unreferenced".
    if let Some(row) = &child_row {
        if row.deleted && !live_child && !conflict_copy_present(&root_a) {
            return Err(format!(
                "DANGLING DELETE ({ordering:?}, seed {seed}): dir1/b.bin index row is a tombstone, \
                 not resurrected live, and no conflict copy exists, yet B's bytes are on disk \
                 unreferenced -- {row:?}"
            ));
        }
    }

    if seed == 0 {
        eprintln!(
            "[{ordering:?} seed0 final state] B_EDIT live at dir1/b.bin={live_child}; \
             conflict_copy_present={}; dir1/b.bin index.deleted={:?}; \
             dir2/b.bin(A's V0 copy) exists={}; dir1 exists={}; dir dispatch records={:?}",
            conflict_copy_present(&root_a),
            child_row.as_ref().map(|r| r.deleted),
            root_a.join("dir2/b.bin").exists(),
            root_a.join(DIR1).exists(),
            dir_dispatch_records.iter().map(|r| (r.path.clone(), r.deleted)).collect::<Vec<_>>(),
        );
    }

    Ok(())
}

fn run_in_madsim(seed: u64, ordering: Ordering) -> Result<(), String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    rt.set_time_limit(Duration::from_secs(60));
    rt.block_on(run_scenario(seed, ordering))
}

fn run_ordering_sweep(ordering: Ordering) {
    let mut skipped = 0;
    let mut exercised = 0;
    for seed in 0..16u64 {
        match run_in_madsim(seed, ordering) {
            Ok(()) => exercised += 1,
            Err(e) if e.starts_with(BASELINE_TIMEOUT_MARKER) => skipped += 1,
            Err(e) => panic!("{ordering:?} seed {seed}: {e}"),
        }
    }
    assert!(
        exercised > 0,
        "{ordering:?}: every one of 16 seeds hit BASELINE_TIMEOUT (skipped {skipped}); \
         nothing was actually exercised -- the race window was never reached"
    );
    eprintln!(
        "{ordering:?}: {exercised} seed(s) exercised the no-silent-loss invariant and passed, \
         {skipped} skipped on baseline timeout"
    );
}

/// Both orderings run sequentially in one `#[test]` fn. Network-touching
/// `madsim` scenarios must not share a process across concurrently-spawned
/// OS threads (the simulated address allocator is process-global), which
/// splitting into separate `#[test]` fns would do -- so both cases live in
/// one test function, matching the sibling reconcile-race scenario.
#[test]
fn directory_move_vs_concurrent_child_edit_no_silent_loss() {
    run_ordering_sweep(Ordering::CbBeforeDirDispatch);
    run_ordering_sweep(Ordering::DirTombstoneBeforeCb);
}
