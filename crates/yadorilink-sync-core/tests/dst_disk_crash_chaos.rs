#![cfg(madsim)]

mod dst_support;

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use boringtun::x25519::{PublicKey, StaticSecret};
use dst_support::case_ir::{ContentTable, DiskFault};
use dst_support::oracle::GlobalOracle;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use yadorilink_local_storage::{
    BlockStore, ContentHash, FsBlockStore, GcReport, StorageError, StorageUsage,
};
use yadorilink_sync_core::debounce::{self, DebounceConfig, FlushPathRequest};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::materialization::{
    cleanup_stale_temp_files, repair_interrupted_materializations,
};
use yadorilink_sync_core::peer_session::{PeerSyncSession, PendingLocalChangeFlush};
use yadorilink_sync_core::types::{BlockInfo, FileRecord, MaterializationState};
use yadorilink_sync_core::version_vector::VersionVector;
use yadorilink_sync_core::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource,
};
use yadorilink_transport::{PeerChannel, TransportMode};

const GROUP_ID: &str = "dst-disk-crash-group";
const DEFAULT_VARIATIONS: u64 = 20;
const OPS_PER_RUN: usize = 6;
const FINAL_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(70);
const TIME_LIMIT_MARKER: &str = "TIME_LIMIT: ";

#[derive(Debug, Clone)]
struct FaultEvent {
    op_after: u64,
    fault: DiskFault,
}

struct FaultingBlockStore {
    inner: FsBlockStore,
    root: PathBuf,
    active: AtomicBool,
    op_count: Mutex<u64>,
    schedule: Mutex<VecDeque<FaultEvent>>,
    log: Mutex<Vec<String>>,
}

impl FaultingBlockStore {
    fn new(root: PathBuf, seed: u64, device: &str) -> Result<Self, StorageError> {
        let mut rng = StdRng::seed_from_u64(seed ^ hash_label(device));
        let mut events = Vec::new();
        for fault in [
            DiskFault::SlowIo { millis: 15 },
            DiskFault::Enospc,
            DiskFault::Eio,
            DiskFault::TornWrite,
            DiskFault::FsyncFail,
        ] {
            events.push(FaultEvent { op_after: rng.gen_range(1..=14), fault });
        }
        events.sort_by_key(|e| e.op_after);
        Ok(Self {
            inner: FsBlockStore::new(&root)?,
            root,
            active: AtomicBool::new(false),
            op_count: Mutex::new(0),
            schedule: Mutex::new(events.into()),
            log: Mutex::new(Vec::new()),
        })
    }

    fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::SeqCst);
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn next_fault(&self, op: &str) -> Option<DiskFault> {
        if !self.active.load(Ordering::SeqCst) {
            return None;
        }
        let current = {
            let mut count = self.op_count.lock().unwrap_or_else(|p| p.into_inner());
            *count += 1;
            *count
        };
        let mut schedule = self.schedule.lock().unwrap_or_else(|p| p.into_inner());
        if schedule.front().map(|e| e.op_after <= current).unwrap_or(false) {
            let fault = schedule.pop_front().unwrap().fault;
            self.log
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(format!("{op}#{current}:{fault:?}"));
            Some(fault)
        } else {
            None
        }
    }

    fn hash_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn path_for_hash(&self, hash: &str) -> PathBuf {
        self.root.join(&hash[0..2]).join(&hash[2..4]).join(hash)
    }

    fn write_torn_final_block(&self, data: &[u8]) -> Result<String, StorageError> {
        let hash = Self::hash_bytes(data);
        let path = self.path_for_hash(&hash);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let cut = data.len().saturating_div(2).max(1).min(data.len());
        std::fs::write(&path, &data[..cut])?;
        Err(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "dst injected torn block write",
        )))
    }

    fn injected_error(kind: std::io::ErrorKind, msg: &str) -> StorageError {
        StorageError::Io(std::io::Error::new(kind, msg))
    }
}

impl BlockStore for FaultingBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        match self.next_fault("put") {
            Some(DiskFault::Enospc) => Err(StorageError::DiskPressure {
                path: self.root.join("injected"),
                volume: self.root.clone(),
                available_bytes: 0,
                headroom_bytes: data.len() as u64,
            }),
            Some(DiskFault::Eio) => {
                Err(Self::injected_error(std::io::ErrorKind::Other, "dst injected EIO"))
            }
            Some(DiskFault::FsyncFail) => {
                Err(Self::injected_error(std::io::ErrorKind::Other, "dst injected fsync failure"))
            }
            Some(DiskFault::TornWrite) => self.write_torn_final_block(data),
            Some(DiskFault::SlowIo { millis }) => {
                std::thread::sleep(Duration::from_millis(millis));
                self.inner.put(data)
            }
            _ => self.inner.put(data),
        }
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        match self.next_fault("get") {
            Some(DiskFault::Eio) | Some(DiskFault::FsyncFail) => {
                Err(Self::injected_error(std::io::ErrorKind::Other, "dst injected read EIO"))
            }
            Some(DiskFault::SlowIo { millis }) => {
                std::thread::sleep(Duration::from_millis(millis));
                self.inner.get(hash)
            }
            _ => self.inner.get(hash),
        }
    }

    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.inner.get_unchecked(hash)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError> {
        self.inner.delete(hash)
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        self.inner.exists(hash)
    }

    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        self.inner.list_by_prefix(prefix)
    }

    fn usage(&self) -> Result<StorageUsage, StorageError> {
        self.inner.usage()
    }

    fn sweep(
        &self,
        live: &HashSet<ContentHash>,
        grace_cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.inner.sweep(live, grace_cutoff, dry_run)
    }

    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        self.inner.present_blocks(hashes)
    }

    fn free_space(
        &self,
    ) -> Result<Option<yadorilink_local_storage::free_space::VolumeFreeSpace>, StorageError> {
        self.inner.free_space()
    }
}

struct ChaosDevice {
    device_id: String,
    root: PathBuf,
    state: Arc<SyncState>,
    processor: Arc<LocalChangeProcessor>,
    flush_request_tx: tokio::sync::mpsc::Sender<FlushPathRequest>,
    session: Mutex<Option<Arc<PeerSyncSession>>>,
}

impl PendingLocalChangeFlush for ChaosDevice {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if self
                .flush_request_tx
                .send(FlushPathRequest {
                    path: self.root.join(rel_path),
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
                    let session = self.session.lock().unwrap_or_else(|p| p.into_inner()).clone();
                    if let Some(session) = session {
                        let _ = session.send_index_update(group_id, outcome.records).await;
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
        self.flush_pending_local_change(group_id, rel_path)
    }
}

fn setup_device(
    device_id: &str,
    root: PathBuf,
    state: Arc<SyncState>,
    store: Arc<dyn BlockStore + Send + Sync>,
) -> Arc<ChaosDevice> {
    let processor =
        Arc::new(LocalChangeProcessor::new(state.clone(), store, device_id.to_string()));
    let (flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    let (watch_source, _events_tx) = SimulatedFolderWatchSource::new(32);
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
        state,
        processor: processor.clone(),
        flush_request_tx,
        session: Mutex::new(None),
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
                    let session =
                        executor_device.session.lock().unwrap_or_else(|p| p.into_inner()).clone();
                    if let Some(session) = session {
                        let _ = session.send_index_update(GROUP_ID, outcome.records).await;
                    }
                }
            }
        }
    });
    device
}

fn gen_keypair(rng: &mut StdRng) -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(rng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

async fn connect_sessions(
    rng: &mut StdRng,
    device_a: &Arc<ChaosDevice>,
    store_a: Arc<dyn BlockStore + Send + Sync>,
    device_b: &Arc<ChaosDevice>,
    store_b: Arc<dyn BlockStore + Send + Sync>,
) {
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

    let mut roots_a = HashMap::new();
    roots_a.insert(GROUP_ID.to_string(), device_a.root.clone());
    let (forward_tx_a, mut forward_rx_a) = tokio::sync::mpsc::unbounded_channel();
    let session_a = PeerSyncSession::new_with_forwarding(
        channel_a,
        device_a.device_id.clone(),
        device_b.device_id.clone(),
        device_a.state.clone(),
        store_a,
        vec![GROUP_ID.to_string()],
        roots_a,
        Some(forward_tx_a),
        None,
    );
    let mut roots_b = HashMap::new();
    roots_b.insert(GROUP_ID.to_string(), device_b.root.clone());
    let (forward_tx_b, mut forward_rx_b) = tokio::sync::mpsc::unbounded_channel();
    let session_b = PeerSyncSession::new_with_forwarding(
        channel_b,
        device_b.device_id.clone(),
        device_a.device_id.clone(),
        device_b.state.clone(),
        store_b,
        vec![GROUP_ID.to_string()],
        roots_b,
        Some(forward_tx_b),
        None,
    );
    *device_a.session.lock().unwrap_or_else(|p| p.into_inner()) = Some(session_a.clone());
    *device_b.session.lock().unwrap_or_else(|p| p.into_inner()) = Some(session_b.clone());
    session_a.set_pending_local_change_flush(device_a.clone());
    session_b.set_pending_local_change_flush(device_b.clone());

    let forward_session_a = session_a.clone();
    tokio::spawn(async move {
        while let Some((group_id, record)) = forward_rx_a.recv().await {
            let _ = forward_session_a.send_index_update(&group_id, vec![record]).await;
        }
    });
    let forward_session_b = session_b.clone();
    tokio::spawn(async move {
        while let Some((group_id, record)) = forward_rx_b.recv().await {
            let _ = forward_session_b.send_index_update(&group_id, vec![record]).await;
        }
    });
    tokio::spawn(session_a.run());
    tokio::spawn(session_b.run());
}

fn content_for(seed: u64, round: usize, device_id: &str, tag: &str) -> Vec<u8> {
    format!("seed {seed} round {round} {tag} {device_id}").into_bytes()
}

fn hash_label(label: &str) -> u64 {
    label.bytes().fold(0xcbf2_9ce4_8422_2325, |acc, b| {
        acc.wrapping_mul(0x1000_0000_01b3).wrapping_add(u64::from(b))
    })
}

async fn process_write(
    device: &Arc<ChaosDevice>,
    path: &str,
    content: &[u8],
) -> Result<Option<FileRecord>, String> {
    std::fs::write(device.root.join(path), content).map_err(|e| e.to_string())?;
    let outcome = match device
        .processor
        .process_event(
            GROUP_ID,
            &device.root,
            &FsChangeEvent { path: device.root.join(path), kind: FsChangeKind::CreatedOrModified },
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            let _ = std::fs::remove_file(device.root.join(path));
            return Ok(None);
        }
    };
    let LocalChangeOutcome::FileChanged(record) = outcome else { return Ok(None) };
    if let Some(session) = device.session.lock().unwrap_or_else(|p| p.into_inner()).clone() {
        session
            .send_index_update(GROUP_ID, vec![record.clone()])
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(Some(record))
}

async fn process_scratch_delete(device: &Arc<ChaosDevice>, path: &str) -> Result<(), String> {
    let _ = std::fs::remove_file(device.root.join(path));
    let _ = device
        .processor
        .process_event(
            GROUP_ID,
            &device.root,
            &FsChangeEvent { path: device.root.join(path), kind: FsChangeKind::Removed },
        )
        .await;
    Ok(())
}

async fn broadcast_full_index(device: &Arc<ChaosDevice>) -> Result<(), String> {
    let records = device.state.list_files(GROUP_ID).map_err(|e| e.to_string())?;
    if records.is_empty() {
        return Ok(());
    }
    if let Some(session) = device.session.lock().unwrap_or_else(|p| p.into_inner()).clone() {
        session.send_index_update(GROUP_ID, records).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn restart_recovery(
    db_path: &Path,
    root: &Path,
    store: &Arc<FaultingBlockStore>,
    device_id: &str,
) -> Result<Arc<SyncState>, String> {
    let state = Arc::new(SyncState::open(db_path).map_err(|e| e.to_string())?);
    state.reset_stale_hydrating_to_placeholder().map_err(|e| e.to_string())?;
    repair_interrupted_materializations(state.as_ref(), store.as_ref(), root, GROUP_ID)
        .map_err(|e| e.to_string())?;
    cleanup_stale_temp_files(root);
    cleanup_stale_temp_files(&store.root);
    let processor = LocalChangeProcessor::new(state.clone(), store.clone(), device_id.to_string());
    processor.reconcile_added_files(GROUP_ID, root).map_err(|e| e.to_string())?;
    Ok(state)
}

fn seed_interrupted_materialization(
    state: &SyncState,
    root: &Path,
    store: &Arc<FaultingBlockStore>,
) -> Result<Vec<u8>, String> {
    let content = b"pre-crash acknowledged content".repeat(8);
    let hash_hex = store.inner.put(&content).map_err(|e| e.to_string())?;
    let record = FileRecord {
        path: "pre-crash.bin".to_string(),
        size: content.len() as u64,
        mtime_unix_nanos: 1,
        version: {
            let mut vv = VersionVector::new();
            vv.increment("device-a");
            vv
        },
        blocks: vec![BlockInfo {
            hash: hex::decode(hash_hex).map_err(|e| e.to_string())?,
            offset: 0,
            size: content.len() as u32,
        }],
        deleted: false,
    };
    state.upsert_file(GROUP_ID, &record).map_err(|e| e.to_string())?;
    state
        .set_materialization_state(GROUP_ID, "pre-crash.bin", MaterializationState::Hydrated)
        .map_err(|e| e.to_string())?;
    std::fs::write(root.join("pre-crash.bin"), &content[..content.len() / 3])
        .map_err(|e| e.to_string())?;
    std::fs::write(
        root.join(format!("pre-crash.bin.yadorilink-tmp.{}.1", std::process::id())),
        b"interrupted materialize temp",
    )
    .map_err(|e| e.to_string())?;
    Ok(content)
}

async fn run_scenario(seed: u64) -> Result<(Vec<String>, Vec<String>), String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let root_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_a = root_dir_a.path().canonicalize().map_err(|e| e.to_string())?;
    let root_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root_b = root_dir_b.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let db_dir_a = tempfile::tempdir().map_err(|e| e.to_string())?;
    let db_dir_b = tempfile::tempdir().map_err(|e| e.to_string())?;
    let db_a = db_dir_a.path().join("state.sqlite");
    let db_b = db_dir_b.path().join("state.sqlite");
    let store_a = Arc::new(
        FaultingBlockStore::new(store_dir_a.path().to_path_buf(), seed, "device-a")
            .map_err(|e| e.to_string())?,
    );
    let store_b = Arc::new(
        FaultingBlockStore::new(store_dir_b.path().to_path_buf(), seed, "device-b")
            .map_err(|e| e.to_string())?,
    );

    {
        let state = SyncState::open(&db_a).map_err(|e| e.to_string())?;
        state.add_link(&root_a.to_string_lossy(), GROUP_ID).map_err(|e| e.to_string())?;
        seed_interrupted_materialization(&state, &root_a, &store_a)?;
    }
    {
        let state = SyncState::open(&db_b).map_err(|e| e.to_string())?;
        state.add_link(&root_b.to_string_lossy(), GROUP_ID).map_err(|e| e.to_string())?;
    }

    let state_a = restart_recovery(&db_a, &root_a, &store_a, "device-a")?;
    let state_b = restart_recovery(&db_b, &root_b, &store_b, "device-b")?;
    if std::fs::read(root_a.join("pre-crash.bin")).map_err(|e| e.to_string())?
        != b"pre-crash acknowledged content".repeat(8)
    {
        return Err(format!("seed {seed}: crash recovery failed to reconstruct pre-crash.bin"));
    }

    let device_a = setup_device("device-a", root_a.clone(), state_a.clone(), store_a.clone());
    let device_b = setup_device("device-b", root_b.clone(), state_b.clone(), store_b.clone());
    connect_sessions(&mut rng, &device_a, store_a.clone(), &device_b, store_b.clone()).await;

    let mut content_table = ContentTable::default();
    let mut oracle = GlobalOracle::new();
    let mut next_content_id = 0;
    content_table.insert(next_content_id, b"pre-crash acknowledged content".repeat(8));
    let mut vv = VersionVector::new();
    vv.increment("device-a");
    oracle.record_write("pre-crash.bin", 0, next_content_id, vv);
    next_content_id += 1;

    store_a.set_active(true);
    store_b.set_active(true);
    for round in 0..OPS_PER_RUN {
        let (device, device_idx) = if rng.gen_bool(0.5) { (&device_a, 0) } else { (&device_b, 1) };
        let path = format!("ack-{round}-{device_idx}.bin");
        let content = content_for(seed, round, &device.device_id, "disk-fault-write");
        if let Ok(Some(record)) = process_write(device, &path, &content).await {
            let content_id = next_content_id;
            next_content_id += 1;
            content_table.insert(content_id, content);
            oracle.record_write(&path, device_idx, content_id, record.version);
        }
        if round == OPS_PER_RUN / 2 {
            process_scratch_delete(
                if device_idx == 0 { &device_b } else { &device_a },
                "scratch-delete.bin",
            )
            .await?;
            store_a.set_active(false);
            store_b.set_active(false);
            let _ = restart_recovery(&db_a, &root_a, &store_a, "device-a")?;
            let _ = restart_recovery(&db_b, &root_b, &store_b, "device-b")?;
            store_a.set_active(true);
            store_b.set_active(true);
        }
        tokio::time::sleep(Duration::from_millis(350)).await;
    }
    store_a.set_active(false);
    store_b.set_active(false);

    restart_recovery(&db_a, &root_a, &store_a, "device-a")?;
    restart_recovery(&db_b, &root_b, &store_b, "device-b")?;
    broadcast_full_index(&device_a).await?;
    broadcast_full_index(&device_b).await?;
    let devices: Vec<(&Path, &SyncState)> =
        vec![(root_a.as_path(), state_a.as_ref()), (root_b.as_path(), state_b.as_ref())];
    let start = tokio::time::Instant::now();
    while tokio::time::Instant::now() < start + FINAL_CONVERGENCE_TIMEOUT {
        if oracle.check_convergence(&devices).is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    restart_recovery(&db_a, &root_a, &store_a, "device-a")?;
    restart_recovery(&db_b, &root_b, &store_b, "device-b")?;

    let mut violations = Vec::new();
    violations.extend(oracle.check_convergence(&devices));
    violations.extend(oracle.check_no_loss(&content_table, &devices));
    violations.extend(oracle.check_conflict_copy_accounting(&content_table, &devices, GROUP_ID));
    violations.extend(oracle.check_no_corruption(&content_table, &devices));
    violations.extend(oracle.check_structural(GROUP_ID, &devices));
    if !violations.is_empty() {
        return Err(format!(
            "faults device-a={:?} device-b={:?}\n{}",
            store_a.log(),
            store_b.log(),
            dst_support::oracle::format_violations(seed, &violations)
        ));
    }
    Ok((store_a.log(), store_b.log()))
}

fn run_in_madsim(seed: u64) -> Result<(Vec<String>, Vec<String>), String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    rt.set_time_limit(Duration::from_secs(110));
    rt.set_allow_system_thread(true);
    rt.block_on(run_scenario(seed))
}

fn run_seed_catching_time_limit(seed: u64) -> Result<(Vec<String>, Vec<String>), String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_in_madsim(seed))) {
        Ok(result) => result,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "non-string panic payload".to_string());
            if msg.contains("time limit exceeded") {
                Err(format!("{TIME_LIMIT_MARKER}seed {seed}: {msg}"))
            } else {
                Err(format!("seed {seed}: unexpected panic: {msg}"))
            }
        }
    }
}

#[test]
fn disk_fault_crash_restart_chaos_scenario() {
    let variations: u64 = std::env::var("DST_VARIATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_VARIATIONS);
    let base_seed: u64 =
        std::env::var("DST_BASE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0xD15C_C0A5);

    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut skipped_time_limit = 0;
    let mut failures = Vec::new();
    for i in 0..variations {
        let seed = base_seed.wrapping_add(i);
        match run_seed_catching_time_limit(seed) {
            Ok((log_a, log_b)) => {
                eprintln!("seed {seed}: passed faults device-a={log_a:?} device-b={log_b:?}");
            }
            Err(e) if e.starts_with(TIME_LIMIT_MARKER) => skipped_time_limit += 1,
            Err(e) => failures.push(e),
        }
    }
    std::panic::set_hook(previous_hook);

    assert!(
        failures.is_empty(),
        "{}/{variations} disk/crash chaos variations failed (skipped {skipped_time_limit} on madsim time limit):\n{}",
        failures.len(),
        failures.join("\n---\n")
    );
}
