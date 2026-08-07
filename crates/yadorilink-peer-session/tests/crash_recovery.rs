//! A daemon-restart integration test proving a local change already
//! committed to this device's
//! `ReplicaCoordinator` (as it would be by `LocalChangeProcessor` processing a
//! real filesystem event) but never yet broadcast to a connected peer —
//! exactly what a crash right after the DB commit but before the
//! outbound `IndexUpdate`/broadcast would leave behind — is durably
//! re-offered to that peer, and re-admitted onto its own DAG, once this
//! device reconnects after "restarting", with no separate persisted
//! retry queue needed.
//!
//! This lives in its own integration-test binary (new file, no edits to
//! the existing `tests/peer_session.rs`) specifically so it can be
//! developed and run independently of that file's own concurrent,
//! unrelated in-flight changes — it duplicates a small slice of that
//! file's test harness (`bind_unused_addr`/`gen_keypair`/`connect_pair`/
//! `spawn_session`) rather than sharing code with it, deliberately, for
//! the same reason.
//!
//! The mechanism this proves already exists and needed no new production
//! code: `PeerSyncSession::run` unconditionally sends a full index for
//! every shared folder group at the *start* of every session (see that
//! function's doc comment, "sends the initial handshake + full index for
//! each shared folder group"), independent of whatever the previous
//! session for the same peer did or didn't manage to broadcast before it
//! died. Combined with `yadorilink-daemon::main`'s startup resuming every
//! link's watcher (a full `scan_existing_files` rescan, which independently
//! catches any change made while the daemon was down entirely), this is
//! what closes the "pending local changes are retried after restart" gap
//! — this test is what turns that into a verified guarantee instead of an
//! assumption.
//!
//! Deliberately scoped to durable DAG delivery only, not disk
//! materialization: since the Convergence Engine split,
//! `handle_change_batch` only admits an incoming change and enqueues a
//! `materialization_jobs` row -- a background engine (owned by
//! `yadorilink-daemon`'s `DaemonState`, not present in this
//! `yadorilink-sync-core`-only integration test) is what actually
//! projects that row onto disk, on its own schedule. Verifying THAT
//! end-to-end belongs in a `yadorilink-daemon` integration test that
//! runs the real engine -- not simulated here via a single manually
//! driven `reconcile_local_materialization_audit` call, which can itself
//! silently swallow an internal projection failure and still report
//! success. `admit_change` refusing to admit a change whose referenced
//! `FileVersion` is missing (re-requesting it instead) is what makes
//! `dag_get_change` succeeding here already strong evidence both the
//! change and its content crossed, without needing to wait on
//! materialization at all.

use std::sync::Arc;

use boringtun::x25519::{PublicKey, StaticSecret};
use ed25519_dalek::SigningKey;
use tokio::net::TcpListener;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_peer_session::peer_session::{PeerSyncSession, PeerSyncSessionDeps};
use yadorilink_transport::PeerChannel;

mod dag_wire_support;
use dag_wire_support::{pinned_authenticator, DagProducer};

const GROUP: &str = "shared-photos";

// Peers connect directly (the relay was removed). This still binds a
// throwaway listener so it hands back a real, unused address and the
// existing call sites keep their shape; `connect_pair` ignores it and wires
// a direct loopback pair instead.
async fn bind_unused_addr() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn gen_keypair() -> (StaticSecret, PublicKey) {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// A persistent device identity: state and block store survive across a
/// simulated crash/restart (only the `PeerSyncSession`/`PeerChannel` pair
/// gets torn down and rebuilt), exactly as a real daemon's on-disk SQLite
/// DB and block store survive a process kill.
struct Device {
    device_id: String,
    root: tempfile::TempDir,
    store: Arc<FsBlockStore>,
    state: Arc<ReplicaCoordinator>,
    signing_key: SigningKey,
    block_serve_engine: Arc<yadorilink_peer_session::block_serve::BlockServeEngine>,
}

impl Device {
    fn new(device_id: &str) -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        // Link `GROUP` at this device's root and declare its startup finished —
        // the only state a real daemon presents to a peer session. Sync roots
        // are derived from the link table in production
        // (`sync_roots_for_groups` reads `list_links`), the apply path re-reads
        // that table for every write it makes, and `wait_group_ready` defers a
        // batch for a live link whose startup never registered a gate. The
        // daemon's link manager supplies both; these tests have no link
        // manager, so stand in for it.
        state.link_repository().add_link(&root.path().to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            root.path(),
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        Device {
            device_id: device_id.to_string(),
            root,
            store: Arc::new(FsBlockStore::new(store_dir.path()).unwrap()),
            state,
            signing_key: SigningKey::from_bytes(&[device_id.as_bytes()[device_id.len() - 1]; 32]),
            // Without this, every BlockRequest this device receives is
            // answered Rejected("source has no serving engine installed")
            // -- there is no more legacy direct-serve fallback for a
            // session with no engine set. A generous, effectively
            // unlimited engine here since this test isn't exercising
            // stage-2 credit/fairness behavior.
            block_serve_engine: yadorilink_peer_session::block_serve::BlockServeEngine::new(
                u64::MAX,
                u64::MAX,
                u64::MAX,
                64,
            ),
        }
    }

    fn sync_roots(&self) -> std::collections::HashMap<String, std::path::PathBuf> {
        std::collections::HashMap::from([(GROUP.to_string(), self.root.path().to_path_buf())])
    }
}

async fn connect_pair(_addr: std::net::SocketAddr) -> (Arc<PeerChannel>, Arc<PeerChannel>) {
    let (secret_a, public_a) = gen_keypair();
    let (secret_b, public_b) = gen_keypair();
    // Direct loopback: bind each side's UDP socket and hand the other its
    // address as the sole direct candidate — the same wiring the daemon's
    // peer orchestrator uses, minus the coordination-plane candidate
    // discovery.
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = socket_a.local_addr().unwrap();
    let addr_b = socket_b.local_addr().unwrap();
    let a = PeerChannel::connect(
        secret_a,
        public_b,
        0,
        vec![addr_b],
        yadorilink_transport::TransportHub::from_socket(socket_a, Some(public_a)),
    )
    .await
    .unwrap();
    let b = PeerChannel::connect(
        secret_b,
        public_a,
        1,
        vec![addr_a],
        yadorilink_transport::TransportHub::from_socket(socket_b, Some(public_b)),
    )
    .await
    .unwrap();
    (Arc::new(a), Arc::new(b))
}

fn spawn_session(
    channel: Arc<PeerChannel>,
    device: &Device,
    peer_device_id: &str,
) -> (Arc<PeerSyncSession>, tokio::task::JoinHandle<()>) {
    let session = PeerSyncSession::new_with_dependencies(
        channel,
        device.device_id.clone(),
        peer_device_id.to_string(),
        device.state.clone(),
        device.store.clone(),
        vec![GROUP.to_string()],
        device.sync_roots(),
        None,
        PeerSyncSessionDeps {
            change_authenticator: pinned_authenticator(&[(
                peer_device_id,
                &SigningKey::from_bytes(&[peer_device_id.as_bytes()[peer_device_id.len() - 1]; 32]),
            )]),
            ..PeerSyncSessionDeps::standalone()
        },
    );
    session.set_block_serve_engine(device.block_serve_engine.clone());
    session.set_full_index_resync_interval(std::time::Duration::from_millis(200));
    let handle = tokio::spawn({
        let session = session.clone();
        async move {
            let _ = session.run().await;
        }
    });
    (session, handle)
}

async fn wait_until<F: Fn() -> bool>(cond: F, timeout: std::time::Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !cond() {
        if tokio::time::Instant::now() >= deadline {
            panic!("condition not met within {timeout:?}");
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// the core restart-retry scenario. Device A commits a local
/// change directly to its own `ReplicaCoordinator`/block store/disk — simulating
/// exactly what `LocalChangeProcessor` would have already durably done
/// for a real filesystem event — but its first session with device B is
/// torn down (simulating a crash) before anything ever broadcasts that
/// change over the wire. A fresh session for the same two persistent
/// device identities (device B's state/store are also untouched by the
/// "crash", exactly like a peer that stayed running throughout) must
/// still deliver and admit it: device B's own DAG ends up with the
/// pre-crash change even though it was never told about it before the
/// "restart" -- see this module's own doc comment for why disk
/// materialization is deliberately out of scope here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_change_committed_before_a_crash_is_reoffered_and_admitted_on_reconnect() {
    let addr = bind_unused_addr().await;
    let device_a = Device::new("device-a");
    let device_b = Device::new("device-b");

    // --- "pre-crash" session pair: an empty initial sync settles first,
    // matching a real daemon's startup handshake before any local edit
    // happens. ---
    let (chan_a1, chan_b1) = connect_pair(addr).await;
    let (session_a1, handle_a1) = spawn_session(chan_a1.clone(), &device_a, "device-b");
    let (session_b1, handle_b1) = spawn_session(chan_b1.clone(), &device_b, "device-a");

    // Give the initial (empty) handshake a moment to complete before the
    // "crash" — a real daemon restart happens well after startup, not
    // mid-handshake.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Device A's local change: committed to its index and written to disk
    // and its block store — everything a real watcher-driven local change
    // would have already durably done — but note nothing here ever calls
    // any send/broadcast method on `session_a1`. This is the exact
    // "committed but never broadcast" state a crash immediately after the
    // DB commit would leave behind.
    let content = b"a change made just before the crash".to_vec();
    std::fs::write(device_a.root.path().join("new-file.txt"), &content).unwrap();
    let producer = DagProducer::new(
        device_a.state.clone(),
        device_a.store.clone(),
        &device_a.device_id,
        device_a.signing_key.clone(),
    );
    // The returned `FileVersion` itself isn't needed: this test's own scope
    // is durable DAG delivery, not disk materialization (see the reconnect
    // wait below) -- the version's content is verified structurally via
    // the admitted `Change`'s own hash instead.
    let _committed = producer.commit_create(GROUP, "new-file.txt", &content, 0);

    // Confirm the peer genuinely never received it pre-crash (the
    // baseline this test would otherwise be trivially true against).
    assert!(
        device_b.state.file_index_repository().get_file(GROUP, "new-file.txt").unwrap().is_none(),
        "sanity check: peer must not already have the file before the crash"
    );

    // --- simulate the crash: abort both sessions' tasks and drop their
    // transport, exactly as a killed daemon process would drop every
    // in-memory connection while leaving `device_a`/`device_b`'s ReplicaCoordinator
    // and block store (their on-disk, persisted state) untouched. ---
    handle_a1.abort();
    handle_b1.abort();
    drop(session_a1);
    drop(session_b1);
    drop(chan_a1);
    drop(chan_b1);

    // --- simulate the restart: a fresh session pair for the same two
    // persistent device identities, as `yadorilink-daemon::main` would
    // build on the next process start (new `PeerSyncSession`s wrapping
    // the same, restart-surviving `ReplicaCoordinator`/`FsBlockStore`). ---
    let (chan_a2, chan_b2) = connect_pair(addr).await;
    let (session_a2, _handle_a2) = spawn_session(chan_a2, &device_a, "device-b");
    let (session_b2, _handle_b2) = spawn_session(chan_b2, &device_b, "device-a");

    wait_until(
        || session_a2.change_dag_negotiated() && session_b2.change_dag_negotiated(),
        std::time::Duration::from_secs(20),
    )
    .await;

    let committed_head =
        device_a.state.sqlite().dag_group_heads(GROUP).unwrap().into_iter().next().unwrap();

    session_a2.announce_local_commit(GROUP).await.unwrap();

    // This test's own scope ends at durable DAG delivery -- the reconnect's
    // post-negotiation frontier announce re-offering the pre-crash change,
    // and device B admitting it (which requires the change's referenced
    // `FileVersion` to have been received and stored too, not just the
    // change envelope itself -- `admit_change` refuses to admit a change
    // whose referenced version is missing and re-requests it instead, so
    // reaching `dag_get_change` succeeding here is already strong evidence
    // both crossed). Materializing that admitted change onto disk is the
    // Convergence Engine's job (a `yadorilink-daemon`-level background
    // process, not present in this `yadorilink-sync-core`-only
    // integration test) -- verifying that end-to-end belongs in a daemon
    // integration test that actually runs `DaemonState`'s real engine, not
    // simulated here via a single manually-driven audit call (which can
    // itself silently swallow an internal projection failure and still
    // report success -- not a substitute for the real thing).
    wait_until(
        || device_b.state.sqlite().dag_get_change(&committed_head).ok().flatten().is_some(),
        std::time::Duration::from_secs(10),
    )
    .await;

    let received_change = device_b
        .state
        .sqlite()
        .dag_get_change(&committed_head)
        .unwrap()
        .expect("pre-crash local change must be re-delivered after reconnect");
    assert_eq!(received_change.compute_hash(), committed_head);
}
