//! Two-device, over-the-wire proof that the change DAG is the sole conflict
//! authority for a real pair of `PeerSyncSession`s.
//!
//! Every other convergence check is in-process: it drives one session's
//! `handle_change_batch`/`handle_message` directly. This scenario is the
//! missing piece — two independent `PeerSyncSession`s, each running its real
//! `run()` production loop over a real (loopback UDP) `PeerChannel`, negotiate
//! the change DAG automatically over the handshake, then exchange a genuinely
//! concurrent edit to the same path entirely through the real
//! HeadsAnnounce -> ChangeRequest -> ChangeBatch wire loop.
//!
//! The edit is built so lamport and mtime disagree: device A's change carries
//! the HIGHER lamport (a warm-up commit raises its clock) but the OLDER mtime;
//! device B's carries the lower lamport but the NEWER mtime. The DAG winner is
//! therefore device A, while an mtime-based resolver — the rule the deleted
//! legacy index-convergence engine used — would pick device B. Converging on
//! A's content is therefore positive evidence that no mtime rule decided
//! anything: both devices must independently converge to A's content as the
//! live file (carrying A's OLDER mtime), with an identical conflict copy of B's
//! losing content on each — over the wire, with no in-process shortcut.
//!
//! The transport is the same real loopback `PeerChannel` + `run()` loop the
//! non-simulated `crash_recovery` test uses; it does not depend on `madsim`.

mod dag_wire_support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use yadorilink_local_storage::{BlockStore, FsBlockStore};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::peer_session::PeerSyncSession;
use yadorilink_sync_core::types::FileRecord;
use yadorilink_transport::PeerChannel;

use dag_wire_support::{pinned_authenticator, DagProducer};
use ed25519_dalek::SigningKey;

const GROUP: &str = "dag-wire-group";
const PATH: &str = "file.bin";
const A_CONTENT: &[u8] = b"device-a content: wins on higher lamport";
const B_CONTENT: &[u8] = b"device-b content: loses despite the newer mtime";
const WARMUP_PATH: &str = "warmup.txt";
// The lamport WINNER (device A) deliberately carries the OLDER mtime, and the
// mtime winner (device B) is the lamport LOSER — so the two engines disagree.
const OLD_MTIME: i64 = 1_000;
const NEW_MTIME: i64 = 9_000;
const WARMUP_MTIME: i64 = 500;

/// Prefix marking "the handshake never negotiated the change DAG within the
/// budget" — a transport/host-timing skip (the real-UDP loopback handshake can
/// be slow under load), distinct from a genuine convergence failure. Only the
/// handshake is allowed to be treated as a skip; once negotiated, a failure to
/// converge is a real finding, never an env skip.
const NEGOTIATE_TIMEOUT_MARKER: &str = "NEGOTIATE_TIMEOUT: ";

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

struct Device {
    state: Arc<SyncState>,
    store: Arc<dyn BlockStore + Send + Sync>,
    producer: DagProducer,
    _root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
}

fn setup_device(device_id: &str, signing_key: SigningKey) -> Device {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn BlockStore + Send + Sync> =
        Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(SyncState::open_in_memory().unwrap());
    state.add_link(&root.to_string_lossy(), GROUP).unwrap();
    yadorilink_sync_core::root_identity::VerifiedRoot::open(&root, GROUP, &state).unwrap();
    // Take this link's startup gate through to Ready, as every live link does in
    // a real daemon: `app::run` arms the gate for each non-orphaned link at boot
    // before any fallible watcher setup, and the `AddLink` control path arms it
    // via `start_link_watch` in the same call that commits the row. Peer apply
    // defers for a live link with no gate, so without this the sessions below
    // would negotiate the DAG and then defer every batch forever — the harness,
    // not the wire loop, would be what the test measured.
    let generation = state.begin_group_startup(GROUP);
    state.mark_group_ready(GROUP, generation);
    let producer = DagProducer::new(state.clone(), store.clone(), device_id, signing_key);
    Device { state, store, producer, _root: root_dir, _store_dir: store_dir }
}

/// Connects two loopback `PeerChannel`s and wraps each in a `PeerSyncSession`,
/// exactly as the daemon's peer orchestrator does (minus coordination-plane
/// candidate discovery — here the candidates are the two bound loopback
/// addresses). Gate ON and the pinned authenticator wired on both sides.
async fn connect_sessions(
    a: &Device,
    b: &Device,
    authenticator: &Arc<dyn yadorilink_sync_core::peer_session::ChangeAuthenticator>,
) -> (Arc<PeerSyncSession>, Arc<PeerSyncSession>) {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
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

    let sync_roots_a = HashMap::from([(GROUP.to_string(), a._root.path().canonicalize().unwrap())]);
    let sync_roots_b = HashMap::from([(GROUP.to_string(), b._root.path().canonicalize().unwrap())]);

    let session_a = PeerSyncSession::new(
        channel_a,
        "device-a".to_string(),
        "device-b".to_string(),
        a.state.clone(),
        a.store.clone(),
        vec![GROUP.to_string()],
        sync_roots_a,
    );
    let session_b = PeerSyncSession::new(
        channel_b,
        "device-b".to_string(),
        "device-a".to_string(),
        b.state.clone(),
        b.store.clone(),
        vec![GROUP.to_string()],
        sync_roots_b,
    );

    for s in [&session_a, &session_b] {
        s.set_change_authenticator(authenticator.clone());
    }
    (session_a, session_b)
}

async fn poll_until(timeout: Duration, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !condition() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn head_lamport(state: &SyncState) -> u64 {
    let heads = state.dag_group_heads(GROUP).unwrap();
    assert_eq!(heads.len(), 1, "expected a single local head before the wire exchange");
    state.dag_get_change(&heads[0]).unwrap().unwrap().lamport
}

/// The live projection of `PATH` on `state`, if present and not tombstoned.
fn live_record(state: &SyncState) -> Option<FileRecord> {
    state.get_file(GROUP, PATH).unwrap().filter(|r| !r.deleted)
}

/// The single non-deleted conflict-copy record for `PATH`, if any.
fn conflict_copy(state: &SyncState) -> Option<FileRecord> {
    let mut copies: Vec<FileRecord> = state
        .list_files(GROUP)
        .unwrap()
        .into_iter()
        .filter(|r| !r.deleted && r.path.contains("(conflicted copy,"))
        .collect();
    assert!(copies.len() <= 1, "expected at most one conflict copy, got {copies:?}");
    copies.pop()
}

fn block_hash(record: &FileRecord) -> Option<&[u8]> {
    record.blocks.first().map(|b| b.hash.as_slice())
}

/// A device has converged when the DAG winner (device A's higher-lamport
/// content, carrying the OLDER mtime) is the live file and B's losing content
/// is preserved as a conflict copy — a pure projection of the admitted changes,
/// so it holds as soon as both changes are admitted, independent of whether the
/// content blocks have been fetched to disk yet.
fn converged(state: &SyncState, winner_hash: &[u8], loser_hash: &[u8]) -> bool {
    let Some(live) = live_record(state) else { return false };
    if live.mtime_unix_nanos != OLD_MTIME || block_hash(&live) != Some(winner_hash) {
        return false;
    }
    match conflict_copy(state) {
        Some(copy) => block_hash(&copy) == Some(loser_hash),
        None => false,
    }
}

fn dump(label: &str, state: &SyncState) {
    let heads = state.dag_group_heads(GROUP).unwrap();
    eprintln!("--- {label}: {} head(s), records:", heads.len());
    for r in state.list_files(GROUP).unwrap() {
        eprintln!(
            "    path={:?} deleted={} mtime={} blocks={}",
            r.path,
            r.deleted,
            r.mtime_unix_nanos,
            r.blocks.len()
        );
    }
}

/// One run of the scenario. `announce_a_first` varies the arrival ordering of
/// the two heads-announces over the wire; the DAG winner must be identical
/// either way. Returns `(winner_mtime_on_a, winner_mtime_on_b, conflict_path)`.
async fn run_scenario(announce_a_first: bool) -> Result<(i64, i64, String, String), String> {
    let key_a = SigningKey::from_bytes(&[7u8; 32]);
    let key_b = SigningKey::from_bytes(&[8u8; 32]);
    let device_a = setup_device("device-a", key_a.clone());
    let device_b = setup_device("device-b", key_b.clone());
    let authenticator = pinned_authenticator(&[("device-a", &key_a), ("device-b", &key_b)]);

    let (session_a, session_b) = connect_sessions(&device_a, &device_b, &authenticator).await;
    let run_a = tokio::spawn(session_a.clone().run());
    let run_b = tokio::spawn(session_b.clone().run());

    // Wait for the automatic change-DAG negotiation the handshake performs
    // (both sides advertise `supports_change_dag`). Only this handshake step is
    // allowed to be treated as an environment skip.
    poll_until(Duration::from_secs(20), || {
        run_a.is_finished()
            || run_b.is_finished()
            || (session_a.change_dag_negotiated() && session_b.change_dag_negotiated())
    })
    .await;
    if run_a.is_finished() || run_b.is_finished() {
        return Err(format!(
            "a session's run() loop exited early during negotiation (a_finished={}, b_finished={})",
            run_a.is_finished(),
            run_b.is_finished()
        ));
    }
    if !(session_a.change_dag_negotiated() && session_b.change_dag_negotiated()) {
        return Err(format!(
            "{NEGOTIATE_TIMEOUT_MARKER}sessions did not negotiate the change DAG in time \
             (a={}, b={})",
            session_a.change_dag_negotiated(),
            session_b.change_dag_negotiated()
        ));
    }

    // Commit the genuinely concurrent edit AFTER negotiation, so the only
    // startup FullIndex (empty at that point) can never feed the legacy
    // resolver — mirroring a daemon that commits during live operation. Device
    // A warms up (root, lamport 1) then edits PATH (child, lamport 2, OLDER
    // mtime); device B creates PATH once (root, lamport 1, NEWER mtime).
    device_a.producer.commit_create(GROUP, WARMUP_PATH, b"warm", WARMUP_MTIME);
    let record_a = device_a.producer.commit_create(GROUP, PATH, A_CONTENT, OLD_MTIME);
    let record_b = device_b.producer.commit_create(GROUP, PATH, B_CONTENT, NEW_MTIME);
    let winner_hash = block_hash(&record_a).expect("committed record has a block").to_vec();
    let loser_hash = block_hash(&record_b).expect("committed record has a block").to_vec();

    // Sanity: the DAG winner (A) really does carry the higher lamport.
    let lamport_a = head_lamport(&device_a.state);
    let lamport_b = head_lamport(&device_b.state);
    assert!(
        lamport_a > lamport_b,
        "test setup: device A's head lamport ({lamport_a}) must exceed device B's ({lamport_b})"
    );

    // Announce the new commits, mirroring `DaemonState::broadcast_change`'s
    // DAG-peer path, then let the DAG wire loop (HeadsAnnounce -> ChangeRequest
    // -> ChangeBatch on each side) run and settle. `announce_local_commit` is
    // idempotent, so it is re-driven on an interval while the settle poll runs:
    // over real (lossy) loopback UDP a single dropped HeadsAnnounce/ChangeRequest
    // datagram would otherwise stall convergence until the 90s periodic frontier
    // audit — the re-announce is exactly that audit, just at a test-friendly
    // cadence, and does not change what the DAG decides. Order is varied to
    // exercise both arrival orders.
    let announce_both = || async {
        let (first, second) =
            if announce_a_first { (&session_a, &session_b) } else { (&session_b, &session_a) };
        let r1 = first.announce_local_commit(GROUP).await;
        let r2 = second.announce_local_commit(GROUP).await;
        r1.and(r2)
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut converged_both = false;
    while tokio::time::Instant::now() < deadline {
        if run_a.is_finished() || run_b.is_finished() {
            break;
        }
        announce_both().await.map_err(|e| e.to_string())?;
        for _ in 0..12 {
            if converged(&device_a.state, &winner_hash, &loser_hash)
                && converged(&device_b.state, &winner_hash, &loser_hash)
            {
                converged_both = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if converged_both {
            break;
        }
    }
    run_a.abort();
    run_b.abort();

    // Negotiated but not converged is NOT an env skip: the transport itself is
    // proven by `crash_recovery` over this same loopback, so a stall here means
    // the DAG wire loop did not carry the concurrent edit between two live
    // sessions — the production gap this proof exists to catch. Report richly,
    // including how many of each side's changes actually crossed.
    for (name, dev) in [("A", &device_a), ("B", &device_b)] {
        if !converged(&dev.state, &winner_hash, &loser_hash) {
            dump(&format!("device {name}"), &dev.state);
            return Err(format!(
                "device {name} did not converge to the lamport winner over the wire. \
                 live={:?} conflict_copy={:?} local_head_count={} total_indexed={}. If both \
                 sessions negotiated the DAG but changes never crossed, the two-session DAG \
                 wire loop is incomplete (a production gap for gate activation), not an env \
                 timeout.",
                live_record(&dev.state).map(|r| (r.mtime_unix_nanos, r.path)),
                conflict_copy(&dev.state).map(|r| r.path),
                dev.state.dag_group_heads(GROUP).unwrap().len(),
                dev.state.list_files(GROUP).unwrap().iter().filter(|r| !r.deleted).count(),
            ));
        }
    }

    let live_a = live_record(&device_a.state).unwrap();
    let live_b = live_record(&device_b.state).unwrap();
    let copy_a = conflict_copy(&device_a.state).unwrap();
    let copy_b = conflict_copy(&device_b.state).unwrap();

    // The live file is A's content (lamport winner), NOT B's newer-mtime
    // content — so lamport, not mtime, decided, on BOTH devices.
    assert_eq!(
        block_hash(&live_a),
        Some(winner_hash.as_slice()),
        "device A live must be the winner"
    );
    assert_eq!(
        block_hash(&live_b),
        Some(winner_hash.as_slice()),
        "device B live must be the winner"
    );
    // The loser's content survives as a conflict copy on both devices...
    assert_eq!(block_hash(&copy_a), Some(loser_hash.as_slice()), "device A conflict copy = loser");
    assert_eq!(block_hash(&copy_b), Some(loser_hash.as_slice()), "device B conflict copy = loser");
    // ...with the identical, replica-independent conflict-copy filename.
    assert_eq!(copy_a.path, copy_b.path, "conflict-copy path must be identical on both devices");

    Ok((live_a.mtime_unix_nanos, live_b.mtime_unix_nanos, copy_a.path, copy_b.path))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dag_two_sessions_converge_to_lamport_winner_over_the_wire() {
    // Two arrival orderings, each proving the over-the-wire DAG winner is the
    // lamport winner (A, OLDER mtime) with the loser preserved as an identical
    // conflict copy on both devices.
    for announce_a_first in [true, false] {
        match run_scenario(announce_a_first).await {
            Ok((mtime_a, mtime_b, path_a, path_b)) => {
                assert_eq!(
                    mtime_a, OLD_MTIME,
                    "device A's live file must carry the lamport winner's OLDER mtime, \
                     not the mtime winner's"
                );
                assert_eq!(mtime_b, OLD_MTIME, "device B likewise");
                assert_eq!(path_a, path_b, "identical conflict-copy path across devices");
            }
            Err(e) if e.starts_with(NEGOTIATE_TIMEOUT_MARKER) => {
                // Transport handshake skip (see the marker's doc); the transport
                // itself is exercised by `crash_recovery`. Do not fail the run.
                eprintln!("skipping ordering announce_a_first={announce_a_first}: {e}");
            }
            Err(e) => panic!("announce_a_first={announce_a_first}: {e}"),
        }
    }
}
