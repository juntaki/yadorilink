//! DST regression scenario: reproduces the self-echo-race data-loss shape
//! with two real, simulated devices exchanging real wire messages over a
//! real (loopback, `madsim`-simulated) `PeerChannel`, driven by the real
//! `PeerSyncSession::run` production loop -- propagation runs over the
//! change-history (DAG) path, not the legacy index wire: each device signs
//! its own local edits with a per-device Ed25519 key (a wired
//! `ChangeEmitter`), and every session pins both devices' verifying keys
//! through a change authenticator, so a received change is admitted only
//! after signature/authorization verification.
//!
//! Race shape: device A has a genuine local edit still sitting
//! undispatched in its own debounce accumulator (event delivered, quiet
//! period not yet elapsed) when device B's independently-produced,
//! causally-later change for the *same path* arrives over the wire
//! (`HeadsAnnounce` -> `ChangeRequest` -> `ChangeBatch`). Without
//! `PendingLocalChangeFlush` wired, A never turns its undispatched edit
//! into a change before admitting B's, so A materializes B's content over
//! A's own real, not-yet-committed edit -- silent data loss. With the
//! guard wired (this scenario's `SimDevice`, mirroring the daemon's real
//! per-link flush handle), A's edit is force-flushed and committed as a
//! *concurrent* DAG change *before* B's change is admitted, so the two
//! resolve as genuinely concurrent -- the loser is preserved as a
//! `(conflicted copy ...)` sibling rather than silently discarded.
//!
//! A second variant (`BEdit::Tombstone`) covers the same race, but B's
//! causally-later change is a delete rather than a content update --
//! exercising the "apply a tombstone over content about to be
//! force-flushed" path instead of "overwrite content with content".

#![cfg(madsim)]

mod dst_support;

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::dag_store::ChangeEmitter;
use yadorilink_sync_core::debounce::{self, DebounceConfig, FlushPathRequest};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::peer_session::{
    ChangeAuthenticator, PeerSyncSession, PendingLocalChangeFlush,
};
use yadorilink_sync_core::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource,
};
use yadorilink_transport::PeerChannel;

const GROUP_ID: &str = "dst-race-group";
const RACE_PATH: &str = "race.bin";
const SETTLE: Duration = Duration::from_millis(500);
/// Prefix marking an error as "baseline connectivity never established in
/// time" -- a separate, real finding (see this scenario's doc comment)
/// about the direct-path WireGuard handshake under simulated time, not a
/// failure of the race/guard behavior this scenario tests. Callers treat
/// this as a skip, not a scenario failure.
const BASELINE_TIMEOUT_MARKER: &str = "BASELINE_TIMEOUT: ";
/// Prefix marking an error as "the race was hit and device A's edit was
/// lost, exactly as expected for the without-guard case" -- distinct
/// from a genuine scenario failure. See `run_scenario`'s use.
const RACE_REPRODUCED_MARKER: &str = "RACE_REPRODUCED: ";

/// Deterministic per-device Ed25519 signing key for the change-DAG path.
/// Test-only: the byte pattern only needs to be stable and distinct per
/// device so the pinned authenticator can verify each author's changes.
fn device_signing_key(device_id: &str) -> SigningKey {
    let mut seed = [0u8; 32];
    for (slot, byte) in seed.iter_mut().zip(device_id.bytes()) {
        *slot = byte;
    }
    // Guarantee a non-zero, distinct seed even for a short/empty id.
    seed[31] = seed[31].wrapping_add(1);
    SigningKey::from_bytes(&seed)
}

/// The change authenticator every session installs: it pins each device's
/// Ed25519 verifying key and treats every pinned author as a writer -- the
/// change-DAG equivalent of the implicit trust the legacy index wire
/// granted any connected peer. A session admits no received change until an
/// authenticator is present, so both sessions must install this before the
/// first `ChangeBatch` arrives.
struct PinnedAuthenticator {
    keys: HashMap<String, [u8; 32]>,
}

impl ChangeAuthenticator for PinnedAuthenticator {
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.get(device_id).copied()
    }

    fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
        true
    }
}

fn pinned_authenticator(device_ids: &[&str]) -> Arc<PinnedAuthenticator> {
    let keys = device_ids
        .iter()
        .map(|id| (id.to_string(), device_signing_key(id).verifying_key().to_bytes()))
        .collect();
    Arc::new(PinnedAuthenticator { keys })
}

/// Re-drives the idempotent `HeadsAnnounce` for `group_id` on a short
/// cadence until `done` holds or `budget` (simulated time) elapses. A
/// single announce is enough for correctness once the change-DAG is
/// negotiated, but a lossy/racing window can drop the first one; re-driving
/// is a harness-robustness measure (production leans on the periodic
/// head-announce audit, far too slow for a bounded test).
async fn announce_until(
    session: &Arc<PeerSyncSession>,
    group_id: &str,
    budget: Duration,
    mut done: impl FnMut() -> bool,
) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let _ = session.announce_local_commit(group_id).await;
        if done() || tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// This scenario's `PendingLocalChangeFlush` implementation -- the same
/// role `yadorilink-daemon::link_manager::LinkFlushHandle` (paired with
/// `impl PendingLocalChangeFlush for DaemonState`) plays in production,
/// simplified for a single link per device (no multi-link lookup table
/// needed here). `guard_enabled` toggles whether this is actually wired
/// to the session (`with_guard`/`without_guard` scenarios below), so the
/// same device-setup code proves both "the race is real" and "the fix
/// closes it" without duplicating the setup.
struct SimDevice {
    root: PathBuf,
    processor: Arc<LocalChangeProcessor>,
    flush_request_tx: tokio::sync::mpsc::Sender<FlushPathRequest>,
    session: OnceLock<Arc<PeerSyncSession>>,
}

impl PendingLocalChangeFlush for SimDevice {
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
                return; // accumulator gone
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
                    // The wired change emitter already turned this force-flushed
                    // local edit into a *concurrent* DAG change inside
                    // `process_flush`; announce the new head so the peer pulls it.
                    if let Some(session) = self.session.get() {
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
                return; // accumulator gone
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
                    // The wired change emitter already turned this force-flushed
                    // local edit into a *concurrent* DAG change inside
                    // `process_flush`; announce the new head so the peer pulls it.
                    if let Some(session) = self.session.get() {
                        let _ = session.announce_local_commit(group_id).await;
                    }
                }
            }
        })
    }
}

/// Device A: the side under test, with its real watcher-boundary/debounce
/// pipeline live (so a local edit can genuinely sit "pending" in it).
struct DeviceA {
    processor: Arc<LocalChangeProcessor>,
    sim: Arc<SimDevice>,
    events_tx: tokio::sync::mpsc::Sender<FsChangeEvent>,
}

fn setup_device_a(root: PathBuf, sync_state: Arc<SyncState>, store: Arc<FsBlockStore>) -> DeviceA {
    // The wired emitter makes every local edit (baseline + the racing edit,
    // once force-flushed) a signed DAG change on this device.
    let processor = Arc::new(
        LocalChangeProcessor::new(sync_state, store, "device-a".to_string())
            .with_change_emitter(Arc::new(ChangeEmitter::new("device-a", device_signing_key("device-a")))),
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

    let executor_processor = processor.clone();
    let executor_root = root.clone();
    tokio::spawn(async move {
        while let Some(flush) = flush_rx.recv().await {
            let _ = executor_processor.process_flush(GROUP_ID, &executor_root, flush).await;
        }
    });

    DeviceA { processor, sim, events_tx }
}

/// Polls `condition` (checked against real state, e.g. disk/index) every
/// 10ms of *simulated* time (fast-forwarded, not real wall-clock) up to
/// `timeout`, returning as soon as it's true. Used only for setup phases
/// whose own internal timing (a handshake, a full-index round trip) isn't
/// what a scenario is testing -- the race itself is sequenced with
/// precise, deliberate `sleep`s instead, see `run_scenario`.
async fn poll_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !condition() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
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

/// Connects two loopback (madsim-simulated UDP) `PeerChannel`s and wraps
/// each in a `PeerSyncSession`, mirroring
/// `yadorilink-daemon::peer_orchestrator`'s real wiring (minus the
/// coordination-plane bootstrap that produces `direct_candidates` in
/// production -- here the candidates are just the two loopback sockets'
/// own bound addresses).
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

    (session_a, session_b)
}

/// What device B's causally-later, independent change is. `ContentUpdate`
/// is the original race shape; `Tombstone` exercises the same race for a
/// delete instead of a content overwrite -- worth testing
/// separately because `reconcile_one_file`'s `Some(local)` branch (see
/// `peer_session.rs`) reaches the same version-vector `compare` this
/// race depends on regardless of `incoming.deleted`, but `materialize`'s
/// handling of "apply a tombstone over content that's about to be
/// force-flushed" is still a materially different code path (deleting a
/// file on disk vs. overwriting it) from the content-vs-content case.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BEdit {
    ContentUpdate,
    Tombstone,
}

/// Runs the race once. `guard_enabled` controls whether device A's
/// `PendingLocalChangeFlush` is wired -- `false` reproduces the
/// pre-fix bug (this device's edit is silently lost), `true` exercises
/// the real fix. `b_edit` selects whether device B's causally-later
/// change is a content update or a tombstone.
async fn run_scenario(seed: u64, guard_enabled: bool, b_edit: BEdit) -> Result<(), String> {
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
    // Baseline: A creates the file locally (real chunking/indexing via
    // process_event, not fabricated), establishing version {device-a: 1}.
    let device_a = setup_device_a(root_a.clone(), state_a.clone(), store_a.clone());
    std::fs::write(root_a.join(RACE_PATH), b"baseline").map_err(|e| e.to_string())?;
    let baseline_outcome = device_a
        .processor
        .process_event(
            GROUP_ID,
            &root_a,
            &FsChangeEvent { path: root_a.join(RACE_PATH), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .map_err(|e| e.to_string())?;
    if !matches!(baseline_outcome, LocalChangeOutcome::FileChanged(_)) {
        return Err(format!("baseline write on device A produced no record: {baseline_outcome:?}"));
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
    if guard_enabled {
        session_a.set_pending_local_change_flush(device_a.sim.clone());
    }

    // Both sessions must pin both authors' keys before any `ChangeBatch`
    // arrives, or received changes are dropped unverified. The
    // `PendingLocalChangeFlush` guard (above) is the only thing that toggles
    // between the with-guard and without-guard cases; the authenticator is
    // installed unconditionally so device A still *receives* B's change in
    // both.
    let authenticator = pinned_authenticator(&["device-a", "device-b"]);
    session_a.set_change_authenticator(authenticator.clone());
    session_b.set_change_authenticator(authenticator);

    let run_a = tokio::spawn(session_a.clone().run());
    let run_b = tokio::spawn(session_b.clone().run());

    // Let the initial direct-path handshake + change-DAG negotiation settle:
    // B adopts A's baseline change (a plain first-adoption fetch/materialize,
    // exercising the real block-fetch path, not manual index fabrication).
    // Negotiation auto-fires the first `HeadsAnnounce`, but we also re-drive
    // A's announce on a short cadence so a dropped one doesn't leave B
    // waiting on the slow periodic head-announce audit. Polled, not a single
    // fixed sleep+check -- the direct UDP path's own liveness/handshake retry
    // timing is itself seed-dependent and isn't part of what this scenario is
    // testing; only the race that follows needs precise timing control.
    announce_until(&session_a, GROUP_ID, Duration::from_secs(5), || {
        run_a.is_finished()
            || run_b.is_finished()
            || std::fs::read(root_b.join(RACE_PATH)).map(|c| c == b"baseline").unwrap_or(false)
    })
    .await;
    poll_until(Duration::from_secs(10), || {
        run_a.is_finished()
            || run_b.is_finished()
            || std::fs::read(root_b.join(RACE_PATH)).map(|c| c == b"baseline").unwrap_or(false)
    })
    .await;
    if run_a.is_finished() || run_b.is_finished() {
        return Err(format!(
            "a session's run() loop exited early (a_finished={}, b_finished={})",
            run_a.is_finished(),
            run_b.is_finished()
        ));
    }
    let baseline_on_b = std::fs::read(root_b.join(RACE_PATH)).map_err(|e| {
        let indexed = state_b.get_file(GROUP_ID, RACE_PATH).ok().flatten();
        format!(
            "{BASELINE_TIMEOUT_MARKER}device B never adopted the baseline within the poll \
                 timeout (index row: {indexed:?}): {e} -- separately discovered: this can mean a \
                 genuine WireGuard handshake livelock under simulated time (both peers' \
                 direct-path retries landing in lockstep), not a bug in this scenario or the \
                 guard under test; "
        )
    })?;
    if baseline_on_b != b"baseline" {
        return Err(format!(
            "device B's adopted baseline content is wrong: {:?}",
            String::from_utf8_lossy(&baseline_on_b)
        ));
    }

    // The race: A writes its own real edit and delivers the watcher
    // event into its own debounce accumulator (now genuinely pending --
    // not yet dispatched, since the debounce quiet period hasn't
    // elapsed), *before* B's causally-later update arrives.
    let a_edit_content = format!("device A's real edit, seed {seed}");
    std::fs::write(root_a.join(RACE_PATH), a_edit_content.as_bytes()).map_err(|e| e.to_string())?;
    device_a
        .events_tx
        .send(FsChangeEvent { path: root_a.join(RACE_PATH), kind: FsChangeKind::CreatedOrModified })
        .await
        .map_err(|_| "device A's watcher channel closed early".to_string())?;
    // Give the accumulator a moment to register the event as pending
    // (well under DebounceConfig::default.quiet_period) without
    // letting it dispatch.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // B produces its own, independent, causally-later change directly
    // (process_event, not through B's own watcher/debounce -- B isn't
    // the side under test here, only its *result* matters) and
    // broadcasts it to A over the real channel. Content update or
    // tombstone, per `b_edit`.
    let b_kind = match b_edit {
        BEdit::ContentUpdate => {
            std::fs::write(root_b.join(RACE_PATH), b"device B's edit")
                .map_err(|e| e.to_string())?;
            FsChangeKind::CreatedOrModified
        }
        BEdit::Tombstone => {
            std::fs::remove_file(root_b.join(RACE_PATH)).map_err(|e| e.to_string())?;
            FsChangeKind::Removed
        }
    };
    let b_outcome = device_b_process_event(&state_b, &store_b, &root_b, b_kind).await?;
    let LocalChangeOutcome::FileChanged(b_record) = b_outcome else {
        return Err(format!("device B's change produced no record: {b_outcome:?}"));
    };
    if b_edit == BEdit::Tombstone && !b_record.deleted {
        return Err(format!("device B's tombstone record wasn't marked deleted: {b_record:?}"));
    }

    // Propagate B's causally-later change over the change-DAG: the wired
    // emitter already committed it as a local DAG head inside
    // `device_b_process_event`; announcing the head drives A's session to
    // pull and apply it (HeadsAnnounce -> ChangeRequest -> ChangeBatch),
    // which (if guard_enabled) triggers A's own force-flush round trip. The
    // re-drive window is bounded well under the debounce quiet period (300ms)
    // so A's own edit is still pending when B's change lands -- keeping the
    // race real. (A DAG-applied index row carries an empty version vector,
    // so there is no cheap positive "B arrived" signal to gate on here;
    // the bounded re-drive guarantees delivery either way.)
    announce_until(&session_b, GROUP_ID, Duration::from_millis(200), || false).await;

    // Let A's PeerSyncSession::run finish processing B's update, including
    // (if guard_enabled) A's own force-flush + conflict-copy materialization.
    tokio::time::sleep(SETTLE).await;
    run_a.abort();
    run_b.abort();

    let survived = a_edit_survives(&root_a, &a_edit_content);
    if guard_enabled {
        if !survived {
            return Err(format!(
                "seed {seed}: with the guard wired, device A's edit was still lost -- expected \
                 it to survive as live content or a conflict-copy"
            ));
        }
    } else if !survived {
        // The bug this scenario reproduces: without the guard, device A's
        // real, undispatched edit is silently overwritten by device B's
        // causally-later update. `RACE_REPRODUCED_MARKER` distinguishes
        // "the race was hit and lost the edit as expected" from a
        // genuine test-infra error (`BASELINE_TIMEOUT_MARKER`) -- both
        // currently surface as `Err`, but callers need to tell them
        // apart (see `self_echo_race_scenario`).
        return Err(format!("{RACE_REPRODUCED_MARKER}seed {seed}: device A's edit was lost"));
    }
    Ok(())
}

async fn device_b_process_event(
    state_b: &Arc<SyncState>,
    store_b: &Arc<FsBlockStore>,
    root_b: &Path,
    kind: FsChangeKind,
) -> Result<LocalChangeOutcome, String> {
    let processor = LocalChangeProcessor::new(state_b.clone(), store_b.clone(), "device-b".to_string())
        .with_change_emitter(Arc::new(ChangeEmitter::new("device-b", device_signing_key("device-b"))));
    processor
        .process_event(GROUP_ID, root_b, &FsChangeEvent { path: root_b.join(RACE_PATH), kind })
        .await
        .map_err(|e| e.to_string())
}

/// True if `expected_content` is present either as the live `race.bin`
/// or as a `race.bin (conflicted copy...)` sibling (`conflict.rs`'s
/// naming convention) -- the two ways a genuine concurrent edit is
/// legitimately allowed to end up, per the no-silent-data-loss
/// invariant's "conflict-copy" branch (documented as an extension point,
/// not yet generalized into `dst_support::check_no_silent_data_loss` --
/// this scenario is the first real exercise of it).
fn a_edit_survives(root: &Path, expected_content: &str) -> bool {
    let live = root.join(RACE_PATH);
    if std::fs::read(&live).map(|c| c == expected_content.as_bytes()).unwrap_or(false) {
        return true;
    }
    let Ok(entries) = std::fs::read_dir(root) else { return false };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("race")
            && name.contains("(conflicted copy")
            && std::fs::read(entry.path())
                .map(|c| c == expected_content.as_bytes())
                .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn run_in_madsim(seed: u64, guard_enabled: bool, b_edit: BEdit) -> Result<(), String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    rt.set_time_limit(Duration::from_secs(30));
    rt.block_on(run_scenario(seed, guard_enabled, b_edit))
}

/// Runs both the without-guard (reproduces the pre-fix bug) and
/// with-guard (the real fix) checks *sequentially in one `#[test]`*,
/// deliberately not as two separate `#[test]` functions.
///
/// Separately discovered while building this scenario: `madsim`'s
/// simulated network state is not safely isolated across *concurrent*
/// `Runtime`s in different OS threads within one process (the simulated
/// addresses it hands out, e.g. `127.0.0.1:1`/`127.0.0.1:2`, come from
/// what appears to be process-global, not per-`Runtime`, allocation) --
/// two network-touching DST scenarios racing in Rust's default
/// multi-threaded test runner corrupted each other's state (a baseline
/// write producing no record at all). Confirmed by `--test-threads=1`
/// making the flakiness disappear entirely. This is scoped to
/// network-touching scenarios specifically: `dst_watcher_debounce.rs`'s
/// `run_many_seeded_variations_in_parallel` genuinely does run many
/// concurrent `Runtime`s safely, because it never touches simulated
/// `net` at all. Merging into one `#[test]` sidesteps the issue without
/// depending on every future CI/local invocation remembering
/// `--test-threads=1` for this specific file.
fn run_self_echo_race_checks(b_edit: BEdit) {
    let mut lost_at_least_once = false;
    let mut skipped_without_guard = 0;
    for seed in 0..16u64 {
        match run_in_madsim(seed, false, b_edit) {
            Ok(()) => {}
            Err(e) if e.starts_with(BASELINE_TIMEOUT_MARKER) => skipped_without_guard += 1,
            Err(e) if e.starts_with(RACE_REPRODUCED_MARKER) => lost_at_least_once = true,
            Err(e) => panic!("seed {seed}: unexpected error (not the race being reproduced): {e}"),
        }
    }
    assert!(
        lost_at_least_once,
        "expected at least one of 16 seeds (skipped {skipped_without_guard} on baseline timeout) \
         to reproduce the pre-fix data-loss race; none did -- the scenario's timing may no \
         longer be hitting the race window"
    );

    let mut skipped_with_guard = 0;
    for seed in 0..16u64 {
        match run_in_madsim(seed, true, b_edit) {
            Ok(()) => {}
            Err(e) if e.starts_with(BASELINE_TIMEOUT_MARKER) => skipped_with_guard += 1,
            Err(e) => panic!("seed {seed}: {e}"),
        }
    }
    assert!(
        skipped_with_guard < 16,
        "every seed hit BASELINE_TIMEOUT -- nothing was actually exercised"
    );
}

/// Runs both `BEdit` variants (content update, then tombstone)
/// sequentially in *one* `#[test]` function.
///
/// Discovered while adding the tombstone variant: splitting it into its
/// own `#[test]` function (even alongside the original as two separate
/// `#[test]`s, both network-touching) reintroduced state corruption
/// identical in symptom to the concurrent-`Runtime` corruption this
/// file's doc comment already describes -- but this time reproducing
/// even under `--test-threads=1` (confirmed: `self_echo_race_scenario_
/// tombstone` alone always passed; only ordered after
/// `self_echo_race_scenario` as a second `#[test]` fn did seed 3 fail,
/// at the very first *local*, pre-networking step). Rust's test harness
/// runs each `#[test]` fn on its own spawned OS thread even at
/// `--test-threads=1` (it serializes *execution*, not thread identity),
/// so this is consistent with the same "madsim's simulated network
/// state isn't process-global-safe across different OS threads" root
/// cause, just triggered by thread reuse across sequential tests rather
/// than genuine concurrency. Merging into one `#[test]` fn (as already
/// done for the two guard states) sidesteps it the same way.
#[test]
fn self_echo_race_scenario() {
    run_self_echo_race_checks(BEdit::ContentUpdate);
    run_self_echo_race_checks(BEdit::Tombstone);
}
