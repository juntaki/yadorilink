#![cfg(madsim)]

mod dst_support;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use boringtun::x25519::{PublicKey, StaticSecret};
use dst_support::case_ir::ContentTable;
use dst_support::oracle::{format_violations, GlobalOracle};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_sync_core::materialization::{
    cleanup_stale_temp_files, repair_interrupted_materializations,
};
use yadorilink_sync_core::peer_session::{
    set_test_clock_override, PeerSyncSession, PendingLocalChangeFlush,
};
use yadorilink_sync_core::types::FileRecord;
use yadorilink_sync_core::version_vector::MAX_VV_COUNTER_JUMP_PER_MESSAGE;
use yadorilink_sync_core::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_transport::{PeerChannel, TransportMode};

const GROUP_ID: &str = "dst-intermittent-catchup";
const CANARY_PATH: &str = "startup-canary.txt";
const HOT_PATH: &str = "hot-counter.txt";
/// Dialed from an original 80ms (~1000x more aggressive than production's
/// `DEFAULT_FULL_INDEX_RESYNC_INTERVAL`, 90s) to a still-fast-for-a-test
/// but realistic-order-of-magnitude 2s, so this scenario reflects a real
/// catch-up cadence rather than manufacturing a guaranteed deadlock via an
/// artificially tight resync loop. The underlying head-of-line deadlock
/// this suite exists to catch is real at this realistic cadence too, given
/// a large enough catch-up batch — it doesn't depend on 80ms specifically.
const RESYNC_INTERVAL: Duration = Duration::from_secs(2);
/// Scaled with `RESYNC_INTERVAL` (same ~1.4x ratio as the original
/// 115ms/80ms pairing) so this still comfortably covers at least one
/// resync tick before checking partial progress.
const PARTIAL_WINDOW: Duration = Duration::from_millis(2_900);
const FINAL_WINDOW: Duration = Duration::from_secs(70);

struct Device {
    device_id: String,
    root: PathBuf,
    state: Arc<SyncState>,
    store: Arc<FsBlockStore>,
    processor: Arc<LocalChangeProcessor>,
    outbound_partitioned: AtomicBool,
    session: OnceLock<Arc<PeerSyncSession>>,
}

impl PendingLocalChangeFlush for Device {
    fn flush_pending_local_change<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        _group_id: &'a str,
        _rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

fn setup_device(device_id: &str) -> Result<Arc<Device>, String> {
    let root_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root = root_dir.path().canonicalize().map_err(|e| e.to_string())?;
    Box::leak(Box::new(root_dir));
    let store_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store = Arc::new(FsBlockStore::new(store_dir.path()).map_err(|e| e.to_string())?);
    Box::leak(Box::new(store_dir));
    let state = Arc::new(SyncState::open_in_memory().map_err(|e| e.to_string())?);
    state.add_link(&root.to_string_lossy(), GROUP_ID).map_err(|e| e.to_string())?;
    let processor =
        Arc::new(LocalChangeProcessor::new(state.clone(), store.clone(), device_id.to_string()));
    Ok(Arc::new(Device {
        device_id: device_id.to_string(),
        root,
        state,
        store,
        processor,
        outbound_partitioned: AtomicBool::new(false),
        session: OnceLock::new(),
    }))
}

fn gen_keypair(rng: &mut StdRng) -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(rng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

async fn connect_sessions(
    rng: &mut StdRng,
    laptop: &Arc<Device>,
    always_on: &Arc<Device>,
) -> Result<(), String> {
    let (secret_a, public_a) = gen_keypair(rng);
    let (secret_b, public_b) = gen_keypair(rng);
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let socket_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let addr_a = socket_a.local_addr().map_err(|e| e.to_string())?;
    let addr_b = socket_b.local_addr().map_err(|e| e.to_string())?;

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
        .map_err(|e| e.to_string())?,
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
        .map_err(|e| e.to_string())?,
    );

    let mut roots_a = HashMap::new();
    roots_a.insert(GROUP_ID.to_string(), laptop.root.clone());
    let (forward_tx_a, mut forward_rx_a) = tokio::sync::mpsc::unbounded_channel();
    let session_a = PeerSyncSession::new_with_forwarding(
        channel_a,
        laptop.device_id.clone(),
        always_on.device_id.clone(),
        laptop.state.clone(),
        laptop.store.clone(),
        vec![GROUP_ID.to_string()],
        roots_a,
        Some(forward_tx_a),
        None,
    );

    let mut roots_b = HashMap::new();
    roots_b.insert(GROUP_ID.to_string(), always_on.root.clone());
    let (forward_tx_b, mut forward_rx_b) = tokio::sync::mpsc::unbounded_channel();
    let session_b = PeerSyncSession::new_with_forwarding(
        channel_b,
        always_on.device_id.clone(),
        laptop.device_id.clone(),
        always_on.state.clone(),
        always_on.store.clone(),
        vec![GROUP_ID.to_string()],
        roots_b,
        Some(forward_tx_b),
        None,
    );
    session_a.set_full_index_resync_interval(RESYNC_INTERVAL);
    session_b.set_full_index_resync_interval(RESYNC_INTERVAL);
    laptop.session.set(session_a.clone()).ok();
    always_on.session.set(session_b.clone()).ok();
    session_a.set_pending_local_change_flush(laptop.clone());
    session_b.set_pending_local_change_flush(always_on.clone());

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
    Ok(())
}

fn pause(device: &Device) -> Result<(), String> {
    device.state.set_paused(&device.root.to_string_lossy(), true).map_err(|e| e.to_string())
}

fn resume(device: &Device) -> Result<(), String> {
    device.state.set_paused(&device.root.to_string_lossy(), false).map_err(|e| e.to_string())
}

fn partition_outbound(device: &Device, partitioned: bool) {
    device.outbound_partitioned.store(partitioned, Ordering::SeqCst);
}

fn is_paused(device: &Device) -> bool {
    device.state.is_paused_for_group(GROUP_ID).unwrap_or(false)
}

async fn send_if_online(device: &Device, record: FileRecord) -> Result<(), String> {
    if !is_paused(device) && !device.outbound_partitioned.load(Ordering::SeqCst) {
        if let Some(session) = device.session.get() {
            session.send_index_update(GROUP_ID, vec![record]).await.map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

async fn broadcast_full_index_as_updates(device: &Device) -> Result<(), String> {
    if is_paused(device) || device.outbound_partitioned.load(Ordering::SeqCst) {
        return Ok(());
    }
    let Some(session) = device.session.get() else { return Ok(()) };
    let records = device.state.list_files(GROUP_ID).map_err(|e| e.to_string())?;
    for chunk in records.chunks(256) {
        session.send_index_update(GROUP_ID, chunk.to_vec()).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn resume_and_broadcast(a: &Device, b: &Device) -> Result<(), String> {
    resume(a)?;
    resume(b)?;
    partition_outbound(a, false);
    partition_outbound(b, false);
    broadcast_full_index_as_updates(a).await?;
    broadcast_full_index_as_updates(b).await?;
    Ok(())
}

async fn poll_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    condition()
}

fn stamp(path: &Path, virtual_now_nanos: i64) -> Result<(), String> {
    let modified = std::time::UNIX_EPOCH + Duration::from_nanos(virtual_now_nanos as u64);
    let file = std::fs::File::options().write(true).open(path).map_err(|e| e.to_string())?;
    file.set_times(std::fs::FileTimes::new().set_modified(modified)).map_err(|e| e.to_string())
}

async fn local_write(
    device: &Arc<Device>,
    path: &str,
    content: Vec<u8>,
    virtual_now_nanos: i64,
) -> Result<FileRecord, String> {
    let full_path = device.root.join(path);
    std::fs::write(&full_path, &content).map_err(|e| e.to_string())?;
    stamp(&full_path, virtual_now_nanos)?;
    let outcome = device
        .processor
        .process_event(
            GROUP_ID,
            &device.root,
            &FsChangeEvent { path: full_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .map_err(|e| e.to_string())?;
    let LocalChangeOutcome::FileChanged(record) = outcome else {
        return Err(format!("write to {path} did not produce FileChanged"));
    };
    send_if_online(device, record.clone()).await?;
    Ok(record)
}

async fn local_delete(device: &Arc<Device>, path: &str) -> Result<Option<FileRecord>, String> {
    match std::fs::remove_file(device.root.join(path)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let outcome = device
        .processor
        .process_event(
            GROUP_ID,
            &device.root,
            &FsChangeEvent { path: device.root.join(path), kind: FsChangeKind::Removed },
        )
        .await
        .map_err(|e| e.to_string())?;
    match outcome {
        LocalChangeOutcome::FileChanged(record) => {
            send_if_online(device, record.clone()).await?;
            Ok(Some(record))
        }
        LocalChangeOutcome::None => Ok(None),
        other => Err(format!("delete to {path} produced unexpected outcome {other:?}")),
    }
}

async fn local_rename(
    device: &Arc<Device>,
    from: &str,
    to: &str,
    content: Vec<u8>,
    virtual_now_nanos: i64,
) -> Result<(Option<FileRecord>, FileRecord), String> {
    let _ = local_delete(device, from).await?;
    let written = local_write(device, to, content, virtual_now_nanos).await?;
    Ok((device.state.get_file(GROUP_ID, from).map_err(|e| e.to_string())?, written))
}

fn content(seed: u64, cycle: usize, seq: usize, device: &str, path: &str) -> Vec<u8> {
    format!("seed={seed} cycle={cycle} seq={seq} device={device} path={path}").into_bytes()
}

fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(root) else { return out };
    for entry in entries.flatten() {
        if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            if let Ok(bytes) = std::fs::read(entry.path()) {
                out.insert(entry.file_name().to_string_lossy().to_string(), bytes);
            }
        }
    }
    out
}

fn compact_convergence_diff(seed: u64, laptop: &Device, always_on: &Device) -> String {
    let a = snapshot(&laptop.root);
    let b = snapshot(&always_on.root);
    let names_a: HashSet<&String> = a.keys().collect();
    let names_b: HashSet<&String> = b.keys().collect();
    let missing_on_laptop: Vec<String> =
        names_b.difference(&names_a).take(12).map(|s| (*s).clone()).collect();
    let missing_on_always_on: Vec<String> =
        names_a.difference(&names_b).take(12).map(|s| (*s).clone()).collect();
    let differing = a
        .iter()
        .filter(|(name, bytes)| b.get(*name).map(|other| other != *bytes).unwrap_or(false))
        .count();
    format!(
        "seed {seed}: convergence failure: laptop_entries={} always_on_entries={} \
         differing_common={} sample_missing_on_laptop={missing_on_laptop:?} \
         sample_missing_on_always_on={missing_on_always_on:?}",
        a.len(),
        b.len(),
        differing,
    )
}

async fn wait_for_canary(laptop: &Device, always_on: &Device) -> Result<(), String> {
    let ok = poll_until(Duration::from_secs(10), || {
        std::fs::read(always_on.root.join(CANARY_PATH)).map(|b| b == b"canary").unwrap_or(false)
            && std::fs::read(laptop.root.join(CANARY_PATH)).map(|b| b == b"canary").unwrap_or(false)
    })
    .await;
    if ok {
        Ok(())
    } else {
        Err("startup canary did not converge".to_string())
    }
}

fn record_write(
    oracle: &mut GlobalOracle,
    table: &mut ContentTable,
    next_content_id: &mut u64,
    path: &str,
    device_idx: usize,
    bytes: Vec<u8>,
    record: &FileRecord,
) {
    let content_id = *next_content_id;
    *next_content_id += 1;
    table.insert(content_id, bytes);
    oracle.record_write(path, device_idx, content_id, record.version.clone());
}

fn record_delete(oracle: &mut GlobalOracle, path: &str, device_idx: usize, record: &FileRecord) {
    oracle.record_delete(path, device_idx, record.version.clone());
}

async fn apply_online_batch(
    rng: &mut StdRng,
    always_on: &Arc<Device>,
    oracle: &mut GlobalOracle,
    table: &mut ContentTable,
    next_content_id: &mut u64,
    seed: u64,
    cycle: usize,
    virtual_now_nanos: &mut i64,
) -> Result<HashSet<String>, String> {
    let mut touched = HashSet::new();
    let batch_len = 45 + rng.gen_range(0..35);
    for seq in 0..batch_len {
        *virtual_now_nanos += 1_000_000;
        set_test_clock_override(*virtual_now_nanos);
        let base = format!("online-{cycle}-{:02}.txt", seq % 28);
        let roll = rng.gen_range(0..10);
        if roll <= 5 {
            let bytes = content(seed, cycle, seq, &always_on.device_id, &base);
            let record = local_write(always_on, &base, bytes.clone(), *virtual_now_nanos).await?;
            record_write(oracle, table, next_content_id, &base, 1, bytes, &record);
            touched.insert(base);
        } else if roll <= 7 {
            if let Some(record) = local_delete(always_on, &base).await? {
                record_delete(oracle, &base, 1, &record);
                touched.insert(base);
            }
        } else {
            let to = format!("online-{cycle}-renamed-{:02}.txt", seq % 28);
            let bytes = content(seed, cycle, seq, &always_on.device_id, &to);
            let (deleted, written) =
                local_rename(always_on, &base, &to, bytes.clone(), *virtual_now_nanos).await?;
            if let Some(record) = deleted {
                record_delete(oracle, &base, 1, &record);
            }
            record_write(oracle, table, next_content_id, &to, 1, bytes, &written);
            touched.insert(base);
            touched.insert(to);
        }
    }
    Ok(touched)
}

async fn apply_offline_laptop_batch(
    rng: &mut StdRng,
    laptop: &Arc<Device>,
    oracle: &mut GlobalOracle,
    table: &mut ContentTable,
    next_content_id: &mut u64,
    seed: u64,
    cycle: usize,
    virtual_now_nanos: &mut i64,
) -> Result<(), String> {
    let batch_len = 18 + rng.gen_range(0..18);
    for seq in 0..batch_len {
        *virtual_now_nanos += 1_000_000;
        set_test_clock_override(*virtual_now_nanos);
        let path = format!("laptop-{cycle}-{:02}.txt", seq % 16);
        let roll = rng.gen_range(0..10);
        if roll <= 5 {
            let bytes = content(seed, cycle, seq, &laptop.device_id, &path);
            let record = local_write(laptop, &path, bytes.clone(), *virtual_now_nanos).await?;
            record_write(oracle, table, next_content_id, &path, 0, bytes, &record);
        } else if roll <= 7 {
            if let Some(record) = local_delete(laptop, &path).await? {
                record_delete(oracle, &path, 0, &record);
            }
        } else {
            let recreated = format!("laptop-{cycle}-recreated-{:02}.txt", seq % 16);
            if let Some(record) = local_delete(laptop, &path).await? {
                record_delete(oracle, &path, 0, &record);
            }
            let bytes = content(seed, cycle, seq, &laptop.device_id, &recreated);
            let record = local_write(laptop, &recreated, bytes.clone(), *virtual_now_nanos).await?;
            record_write(oracle, table, next_content_id, &recreated, 0, bytes, &record);
        }
    }
    Ok(())
}

async fn drive_large_honest_vv_jump(
    always_on: &Arc<Device>,
    oracle: &mut GlobalOracle,
    table: &mut ContentTable,
    next_content_id: &mut u64,
    seed: u64,
    virtual_now_nanos: &mut i64,
) -> Result<(), String> {
    for seq in 0..=MAX_VV_COUNTER_JUMP_PER_MESSAGE {
        *virtual_now_nanos += 1;
        if seq % 250 == 0 {
            set_test_clock_override(*virtual_now_nanos);
        }
        let bytes = content(seed, 999, seq as usize, &always_on.device_id, HOT_PATH);
        let record = local_write(always_on, HOT_PATH, bytes.clone(), *virtual_now_nanos).await?;
        record_write(oracle, table, next_content_id, HOT_PATH, 1, bytes, &record);
    }
    Ok(())
}

async fn run_seed(seed: u64, exercise_large_vv: bool) -> Result<(), String> {
    let _ = tracing_subscriber::fmt::try_init();
    let mut rng = StdRng::seed_from_u64(seed);
    let laptop = setup_device("laptop")?;
    let always_on = setup_device("always-on")?;
    connect_sessions(&mut rng, &laptop, &always_on).await?;

    let mut virtual_now_nanos = (seed as i64).wrapping_mul(1_000_000_000);
    set_test_clock_override(virtual_now_nanos);
    let mut oracle = GlobalOracle::new();
    let mut table = ContentTable::default();
    let mut next_content_id = 0;

    let canary = b"canary".to_vec();
    let canary_record =
        local_write(&laptop, CANARY_PATH, canary.clone(), virtual_now_nanos).await?;
    record_write(
        &mut oracle,
        &mut table,
        &mut next_content_id,
        CANARY_PATH,
        0,
        canary,
        &canary_record,
    );
    wait_for_canary(&laptop, &always_on).await?;

    let mut last_partial_count = 0usize;
    for cycle in 0..4 {
        pause(&laptop)?;
        partition_outbound(&laptop, true);
        partition_outbound(&always_on, true);
        let _touched = apply_online_batch(
            &mut rng,
            &always_on,
            &mut oracle,
            &mut table,
            &mut next_content_id,
            seed,
            cycle,
            &mut virtual_now_nanos,
        )
        .await?;
        apply_offline_laptop_batch(
            &mut rng,
            &laptop,
            &mut oracle,
            &mut table,
            &mut next_content_id,
            seed,
            cycle,
            &mut virtual_now_nanos,
        )
        .await?;
        if cycle == 0 && exercise_large_vv {
            drive_large_honest_vv_jump(
                &always_on,
                &mut oracle,
                &mut table,
                &mut next_content_id,
                seed,
                &mut virtual_now_nanos,
            )
            .await?;
        }

        resume_and_broadcast(&laptop, &always_on).await?;
        tokio::time::sleep(PARTIAL_WINDOW).await;
        let partial_count = snapshot(&laptop.root).len();
        assert!(
            partial_count >= last_partial_count,
            "seed {seed} cycle {cycle}: partial catch-up regressed from {last_partial_count} to {partial_count} entries"
        );
        last_partial_count = partial_count;

        if cycle < 3 {
            pause(&laptop)?;
            partition_outbound(&laptop, true);
            partition_outbound(&always_on, true);
        }
    }

    resume_and_broadcast(&laptop, &always_on).await?;
    let devices: Vec<(&Path, &SyncState)> = vec![
        (laptop.root.as_path(), laptop.state.as_ref()),
        (always_on.root.as_path(), always_on.state.as_ref()),
    ];
    let converged =
        poll_until(FINAL_WINDOW, || oracle.check_convergence(&devices).is_empty()).await;
    if !converged {
        return Err(compact_convergence_diff(seed, &laptop, &always_on));
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    for device in [&laptop, &always_on] {
        let _ = repair_interrupted_materializations(
            &device.state,
            device.store.as_ref(),
            &device.root,
            GROUP_ID,
        );
        cleanup_stale_temp_files(&device.root);
    }

    let mut violations = Vec::new();
    violations.extend(oracle.check_convergence(&devices));
    violations.extend(oracle.check_no_loss(&table, &devices));
    violations.extend(oracle.check_conflict_copy_accounting(&table, &devices, GROUP_ID));
    violations.extend(oracle.check_no_corruption(&table, &devices));
    violations.extend(oracle.check_structural(GROUP_ID, &devices));
    if !violations.is_empty() {
        if violations
            .iter()
            .any(|v| matches!(v.kind, dst_support::oracle::ViolationKind::Convergence))
        {
            return Err(compact_convergence_diff(seed, &laptop, &always_on));
        }
        return Err(format_violations(seed, &violations));
    }

    if exercise_large_vv {
        let laptop_hot = laptop
            .state
            .get_file(GROUP_ID, HOT_PATH)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "laptop never received hot-counter record".to_string())?;
        assert_eq!(
            laptop_hot.version.get(&always_on.device_id),
            MAX_VV_COUNTER_JUMP_PER_MESSAGE + 1,
            "large honest VV advance must fully heal by final stable catch-up"
        );
    }
    Ok(())
}

#[test]
fn intermittent_catchup_chaos_sweep() {
    let base_seed =
        std::env::var("DST_BASE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5EED_CADA);
    let variations = std::env::var("DST_VARIATIONS").ok().and_then(|s| s.parse().ok()).unwrap_or(4);
    let mut failures = Vec::new();
    for offset in 0..variations {
        let seed = base_seed + offset;
        let exercise_large_vv = offset == 0 || std::env::var("DST_LARGE_VV_EVERY_SEED").is_ok();
        let mut rt =
            madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
        rt.set_time_limit(Duration::from_secs(180));
        rt.set_allow_system_thread(true);
        let result = rt.block_on(async move {
            tokio::time::timeout(Duration::from_secs(170), run_seed(seed, exercise_large_vv)).await
        });
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => failures.push(format!("seed {seed}: {e}")),
            Err(_) => failures.push(format!("seed {seed}: timed out")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
