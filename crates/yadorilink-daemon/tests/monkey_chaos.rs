//! Chaos/monkey test: a randomized sequence of concurrent file operations
//! (create, edit, delete, rename) from several real daemon-equivalent
//! devices sharing one folder group, driven at real wall-clock speed over
//! a real relay + coordination server — the same components
//! `e2e_three_devices.rs` uses, but exercising many more, unscripted
//! interleavings than any single hand-written scenario would, in the hope
//! of surfacing race conditions that a fixed test sequence wouldn't
//! happen to hit. Not a regression test for one specific bug — a
//! generic invariant check ("every device converges to the identical
//! final file set") run repeatedly (see `scripts/heat-run.sh`) to build
//! confidence beyond what scripted tests alone can.
//!
//! Seeded via `MONKEY_CHAOS_SEED` (or a freshly generated seed, logged at
//! the start of every run, when that env var is unset) rather than
//! `rand::thread_rng()`, so a failing run's exact interleaving is
//! reproducible: re-run with `MONKEY_CHAOS_SEED=<logged seed> cargo test
//! -p yadorilink-daemon --test monkey_chaos -- --nocapture`. A failing
//! seed is also appended to the checked-in corpus at
//! `tests/dst_corpus/monkey_chaos_seeds.txt`, which `replay_known_failing_
//! seeds` below always re-runs, so a found race becomes a permanent
//! regression check rather than a one-off heat-run finding. Every action
//! taken is still logged via `tracing::info!` so a failure's exact
//! operation sequence is reconstructable from `--nocapture` output too.

mod support;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt as _;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::{Digest, Sha256};
use support::{
    open_file_backed_sync_state, real_entry_names, wait_until_with_context, TestAccount,
};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::{link_manager, peer_orchestrator};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_transport::DeviceKeyPair;

const DEVICE_COUNT: usize = 4;
const CANDIDATE_FILE_COUNT: usize = 8;
const ROUNDS: usize = 40;
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);

fn corpus_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dst_corpus/monkey_chaos_seeds.txt")
}

/// Seeds from a prior failing run, persisted so they're always re-run
/// (see `replay_known_failing_seeds`) instead of only surfacing once on
/// whichever heat-run happened to find them. Blank lines and `#`-prefixed
/// comments are ignored so the corpus file can carry context per seed.
fn load_corpus_seeds() -> Vec<u64> {
    let Ok(contents) = std::fs::read_to_string(corpus_path()) else {
        return Vec::new();
    };
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.parse::<u64>().ok())
        .collect()
}

/// Appends `seed` to the corpus file (creating it/its directory if
/// needed), best-effort -- a failure to persist the seed must not itself
/// panic out of a panic hook.
fn record_failing_seed(seed: u64) {
    let path = corpus_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{seed}");
    }
}

fn seed_from_env_or_random() -> u64 {
    std::env::var("MONKEY_CHAOS_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| rand::thread_rng().gen())
}

struct TestDevice {
    device_id: String,
    keypair: Arc<DeviceKeyPair>,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // daemon-concurrency-tests-file-backed-wal: file-backed WAL (production's
    // concurrency model) instead of open_in_memory's shared-cache backend —
    // see open_file_backed_sync_state's doc comment. Held only to keep the
    // backing temp file alive for the test's duration.
    _index_dir: tempfile::TempDir,
}

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let keypair = Arc::new(DeviceKeyPair::generate());
    let device_id = support::register_device(account, name, keypair.public_bytes()).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_sync_state();
    let sync_state = Arc::new(sync_state);
    let state = DaemonState::new(device_id.clone(), sync_state, store);
    TestDevice {
        device_id,
        keypair,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

async fn start_syncing(
    device: &TestDevice,
    coordination_addr: String,
    relay_addr: SocketAddr,
    access_token: String,
    group_id: &str,
) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.sync_state.add_link(&local_path, group_id).unwrap();
    link_manager::start_link_watch(device.state.clone(), local_path, group_id.to_string()).unwrap();

    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        relay_addr,
        access_token,
        device_id: device.device_id.clone(),
    };
    let keypair = device.keypair.clone();
    let state = device.state.clone();
    tokio::spawn(async move {
        let _ = peer_orchestrator::run(config, keypair, state).await;
    });
}

#[derive(Clone, Copy)]
enum Action {
    WriteNew,
    Edit,
    Delete,
    Rename,
}

/// Real (non-artifact) file entries, keyed by name, valued by a content
/// hash — cheap to compare across devices without holding whole file
/// contents in memory, and immune to `real_entry_names`' own exclusion
/// of transient materialization/probe artifacts.
fn snapshot(root: &std::path::Path) -> HashMap<String, String> {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let content = std::fs::read(root.join(&name)).unwrap_or_default();
            let hash = hex::encode(Sha256::digest(&content));
            (name, hash)
        })
        .collect()
}

/// Diagnostic-only: a device's own index state for `path`, independent of
/// what's actually materialized on disk -- distinguishes "this device's
/// index has no record of this file at all" (propagation never reached
/// it) from "the index has a record but it's not materialized" (e.g.
/// stuck `Hydrating`/`Placeholder`, or held due to a hazard).
fn describe_index_state(state: &DaemonState, group_id: &str, path: &str) -> String {
    let record = state.sync_state.get_file(group_id, path);
    let materialization = state.sync_state.get_materialization_state(group_id, path);
    let held = state.sync_state.get_held_state(group_id, path);
    format!("record={record:?} materialization={materialization:?} held={held:?}")
}

async fn run_chaos(seed: u64) {
    let _ = tracing_subscriber::fmt::try_init();
    let coordination_addr = support::start_coordination_server().await;
    let relay_addr = support::start_relay_server().await;
    let account = support::register_and_login(&coordination_addr, "monkey-chaos@example.com").await;

    let mut devices = Vec::with_capacity(DEVICE_COUNT);
    for i in 0..DEVICE_COUNT {
        devices.push(setup_device(&account, &format!("device-{i}")).await);
    }
    let group_id = support::create_folder_group(&account, "monkey-chaos-group").await;
    for device in &devices {
        support::grant_access(&account, &group_id, &device.device_id).await;
    }
    for device in &devices {
        start_syncing(
            device,
            coordination_addr.clone(),
            relay_addr,
            account.access_token.clone(),
            &group_id,
        )
        .await;
    }

    // Give peer sessions a moment to establish before the chaos begins.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let candidate_names: Vec<String> =
        (0..CANDIDATE_FILE_COUNT).map(|i| format!("chaos-{i:02}.bin")).collect();

    let mut rng = StdRng::seed_from_u64(seed);
    for round in 0..ROUNDS {
        let device_idx = rng.gen_range(0..DEVICE_COUNT);
        let device = &devices[device_idx];
        let name = &candidate_names[rng.gen_range(0..CANDIDATE_FILE_COUNT)];
        let path = device.root.path().join(name);
        // Delete/Rename need `path` to actually exist *on this device's
        // own local view* first -- a real user can only act on a file
        // they can see. Without this check, a delete/rename issued before
        // this device has synced an earlier write from another device
        // would silently no-op (`std::fs::remove_file`/`rename` on a
        // nonexistent path just errors, previously discarded via `let _
        // =`), while still being logged as if it happened -- creating an
        // artificial, test-only mismatch between what was logged and
        // what devices actually converged on, that looked like a sync
        // bug but wasn't one.
        let path_exists = path.exists();
        let action = match rng.gen_range(0..4) {
            0 => Action::WriteNew,
            1 => Action::Edit,
            2 if path_exists => Action::Delete,
            3 if path_exists => Action::Rename,
            _ => Action::WriteNew,
        };
        match action {
            Action::WriteNew | Action::Edit => {
                let content = format!("round {round} device {device_idx} name {name}");
                std::fs::write(&path, content.as_bytes()).unwrap();
                tracing::info!(round, device = %device.device_id, name = %name, "wrote");
            }
            Action::Delete => {
                std::fs::remove_file(&path).unwrap();
                tracing::info!(round, device = %device.device_id, name = %name, "deleted");
            }
            Action::Rename => {
                let other_name = &candidate_names[rng.gen_range(0..CANDIDATE_FILE_COUNT)];
                let other_path = device.root.path().join(other_name);
                std::fs::rename(&path, &other_path).unwrap();
                tracing::info!(
                    round,
                    device = %device.device_id,
                    from = %name,
                    to = %other_name,
                    "renamed"
                );
            }
        }
        // Real, if small and randomized, gap between actions — enough for
        // the debounce accumulator/watcher to see distinct windows most
        // of the time, without making this test glacially slow.
        tokio::time::sleep(Duration::from_millis(rng.gen_range(10..60))).await;
    }

    // A short fixed pause before the stability-wait even starts polling,
    // so the very last round's own debounce window (up to
    // DEFAULT_MAX_FLUSH_INTERVAL, 2s) has a moment to at least begin
    // flushing before the "has anything changed recently" check below
    // starts measuring from a true baseline, rather than measuring
    // "stability" against a snapshot taken while the last round's change
    // hadn't even been indexed yet.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Let everything settle: wait until every device's snapshot has been
    // stable (unchanged from the previous check) for a few consecutive
    // polls, rather than a single point-in-time comparison that could
    // catch mid-flight state.
    let devices_ref = &devices;
    // `wait_until_with_context`'s condition closure is `Fn`, not `FnMut` --
    // interior mutability is how this tracks state (consecutive stable
    // polls, last snapshot) across calls.
    let stable_polls = std::cell::Cell::new(0u32);
    let reset_count = std::cell::Cell::new(0u32);
    let last_snapshots = std::cell::RefCell::new(
        devices_ref
            .iter()
            .map(|d| snapshot(d.root.path()))
            .collect::<Vec<HashMap<String, String>>>(),
    );
    wait_until_with_context(
        || {
            let current: Vec<HashMap<String, String>> =
                devices_ref.iter().map(|d| snapshot(d.root.path())).collect();
            if current == *last_snapshots.borrow() {
                stable_polls.set(stable_polls.get() + 1);
            } else {
                // Diagnostic-only: how many times stability was reset
                // over the whole wait -- distinguishes "occasionally
                // resets, otherwise steadily progressing" (background
                // chatter like the periodic full-index resync/repair
                // tasks briefly touching something, still expected to
                // eventually clear) from "resets constantly, never gets
                // anywhere close" (a genuine ongoing divergence).
                reset_count.set(reset_count.get() + 1);
                stable_polls.set(0);
                *last_snapshots.borrow_mut() = current;
            }
            // `wait_until_with_context` polls every 100ms. This used to
            // require 1100 (110s, to clear DEFAULT_FULL_INDEX_RESYNC_
            // INTERVAL's 90s) on the theory that reaching a correct final
            // state might depend on the periodic full-index resync firing
            // as a recovery mechanism -- but that reasoning predated later
            // fixes to materialization/disk-index divergence handling
            // (which mean ordinary incremental sync, not the 90s resync,
            // is what's expected to converge this promptly in practice).
            // A 110s-of-perfect-quiescence bar, combined with
            // CONVERGENCE_TIMEOUT's own absolute deadline, left too
            // little margin if genuine convergence (four devices, real
            // relay-mediated conflict resolution) happened to finish
            // later than (deadline - 110s) -- observed causing this exact
            // wait to time out despite all devices already holding
            // byte-identical content at that point, a test-timing false
            // failure, not a real divergence.
            //
            // A much shorter window (30, ~3s) then over-corrected the
            // other way: `debounce::DEFAULT_MAX_FLUSH_INTERVAL` alone is
            // 2s, and this is 4 devices each running their own debounce/
            // executor pair plus real relay round trips and reconciliation
            // on top of that -- 3s left too little margin for the *last*
            // chaos round's own change to even finish being indexed and
            // broadcast, let alone received/reconciled/materialized by
            // every peer, causing this wait to declare "stable" while a
            // real in-flight change was still arriving (observed as a
            // spurious index-says-present-but-disk-is-missing mismatch
            // matching this test's original symptom, but actually just
            // mid-flight propagation this wait exited before waiting for).
            // 300 (30s) comfortably clears the debounce pipeline's own
            // worst case with real margin for network/reconcile overhead,
            // while remaining far short of the stale 110s figure. The
            // strict, unconditional equality assertion after this wait
            // (not this heuristic) is what actually proves correctness --
            // this value only trades off how many extra, unneeded polls
            // happen after genuine convergence, never correctness itself.
            stable_polls.get() >= 300
        },
        CONVERGENCE_TIMEOUT,
        || {
            // Full content-hash snapshot (not just names) -- if devices
            // ever time out here despite reporting an identical *name*
            // set, this is what distinguishes "genuinely still-changing
            // content" (a real bug) from "stable_polls kept resetting for
            // some other reason despite nothing actually differing"
            // (e.g. a test-timing artifact in this wait itself).
            let dump = devices_ref
                .iter()
                .enumerate()
                .map(|(i, d)| format!("device-{i} snapshot={:?}", snapshot(d.root.path())))
                .collect::<Vec<_>>()
                .join("\n");
            format!(
                "stability_reset_count={} (how many times the wait's own stability window \
                 restarted; a large count with names already matching suggests content is \
                 still genuinely changing, not just a slow one-time convergence)\n{dump}",
                reset_count.get()
            )
        },
    )
    .await;

    let final_snapshots: Vec<HashMap<String, String>> =
        devices.iter().map(|d| snapshot(d.root.path())).collect();
    let reference = &final_snapshots[0];
    for (i, snap) in final_snapshots.iter().enumerate().skip(1) {
        if snap == reference {
            continue;
        }
        let only_in_reference: Vec<&String> =
            reference.keys().filter(|k| !snap.contains_key(*k)).collect();
        let only_in_other: Vec<&String> =
            snap.keys().filter(|k| !reference.contains_key(*k)).collect();
        let differing_content: Vec<&String> = reference
            .keys()
            .filter(|k| snap.get(*k).is_some_and(|v| v != &reference[*k]))
            .collect();
        let affected: Vec<&String> = only_in_reference
            .iter()
            .chain(&only_in_other)
            .chain(&differing_content)
            .copied()
            .collect();
        let mut index_dump = String::new();
        for name in &affected {
            for (d, device) in devices.iter().enumerate() {
                index_dump.push_str(&format!(
                    "  device-{d} sync_state[{name:?}]: {}\n",
                    describe_index_state(&device.state, &group_id, name)
                ));
            }
        }
        panic!(
            "device-{i} diverged from device-0's final file set after {ROUNDS} random operations\n\
             only on device-0: {only_in_reference:?}\n\
             only on device-{i}: {only_in_other:?}\n\
             present on both but different content: {differing_content:?}\n\
             --- sync_state (index) detail for affected names ---\n{index_dump}"
        );
    }
}

/// Catches a panic inside `run_chaos` (an assertion failure, an
/// `unwrap()`, or the final divergence `panic!`) so the seed can be
/// recorded before the failure is re-raised. Uses `catch_unwind` on the
/// future directly (not `tokio::spawn`, which would require `run_chaos`'s
/// whole future to be `Send` -- it isn't, since `wait_until_with_context`
/// closures below hold `Cell`/`RefCell` state). `AssertUnwindSafe` is
/// sound here because on a caught panic this function immediately
/// re-raises it and the (possibly torn) local state inside `run_chaos` is
/// simply dropped, never observed again.
async fn run_chaos_recording_seed_on_failure(seed: u64) {
    let result = std::panic::AssertUnwindSafe(run_chaos(seed)).catch_unwind().await;
    if let Err(panic_payload) = result {
        record_failing_seed(seed);
        std::panic::resume_unwind(panic_payload);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn random_concurrent_operations_converge_to_an_identical_file_set() {
    let seed = seed_from_env_or_random();
    eprintln!(
        "MONKEY_CHAOS_SEED={seed} (reproduce with: MONKEY_CHAOS_SEED={seed} cargo test -p \
         yadorilink-daemon --test monkey_chaos random_concurrent_operations -- --nocapture)"
    );
    tracing::info!(seed, "starting monkey_chaos run");
    run_chaos_recording_seed_on_failure(seed).await;
}

/// Re-runs every seed recorded in `tests/dst_corpus/monkey_chaos_seeds.txt`
/// (see the module doc comment), so a race this chaos test previously
/// found stays covered by CI/heat-run as a permanent regression check
/// instead of only surfacing again if a future run happens to pick the
/// same interleaving. A no-op (and instantly passing) while the corpus is
/// empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replay_known_failing_seeds() {
    let _ = tracing_subscriber::fmt::try_init();
    for seed in load_corpus_seeds() {
        tracing::info!(seed, "replaying corpus seed");
        run_chaos_recording_seed_on_failure(seed).await;
    }
}
