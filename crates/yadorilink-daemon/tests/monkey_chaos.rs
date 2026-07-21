//! Chaos/monkey test: a randomized sequence of concurrent file operations
//! (create, edit, delete, rename) from several real daemon-equivalent
//! devices sharing one folder group, driven at real wall-clock speed over
//! directly-paired peer sessions, but exercising many more, unscripted
//! interleavings than any single hand-written scenario would, in the hope
//! of surfacing race conditions that a fixed test sequence wouldn't
//! happen to hit. Not a regression test for one specific bug — a
//! generic invariant check ("every device converges to the identical
//! final file set") run repeatedly (see `scripts/heat-run.sh`) to build
//! confidence beyond what scripted tests alone can.
//!
//! Seeded via `MONKEY_CHAOS_SEED` (or a freshly generated seed, logged at
//! the start of every run, when that env var is unset) rather than
//! `rand::random`, so a failing run's exact interleaving is
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
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt as _;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use sha2::{Digest, Sha256};
use support::{
    open_file_backed_sync_state, real_entry_names, wait_until_with_context, TestAccount,
};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::link_manager;
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
        .unwrap_or_else(rand::random)
}

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // Uses file-backed WAL (production's concurrency model) instead of
    // open_in_memory's shared-cache backend — see
    // open_file_backed_sync_state's doc comment. Held only to keep the
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
    // Give the device a change-signing key before its link watch starts, so the
    // change-DAG emitter is wired and local edits actually propagate. Without
    // this, nothing this device writes is ever emitted to its peers.
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

async fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.sync_state.add_link(&local_path, group_id).unwrap();
    link_manager::start_link_watch(device.state.clone(), local_path, group_id.to_string()).unwrap();
}

/// Tears down one seed's daemon mesh when dropped: aborts every paired
/// session's `run()` task and stops every device's link watch (the
/// watcher/debounce/executor/repair tasks `link_manager::start_link_watch`
/// spawned).
///
/// Without this, nothing in this file ever tears a seed's mesh down --
/// `connect_two_daemons`'s session tasks hold *strong* `Arc<DaemonState>`
/// references (via `set_pending_local_change_flush` and friends) and run
/// forever since nothing closes their channel or aborts them, and
/// `start_link_watch`'s tasks are equally permanent until `stop_link_watch`
/// is called. `replay_known_failing_seeds` runs every corpus seed's
/// `run_chaos` sequentially in the *same* process, so without teardown each
/// seed leaves its entire 4-device mesh (12 session tasks plus each
/// device's watcher/debounce/executor/repair tasks and SQLite pool) running
/// underneath the next one -- confirmed as the actual cause of a real CI
/// failure: the second of two corpus seeds failed initial DAG handshake
/// negotiation within its 10s budget, competing with the first seed's
/// still-fully-running mesh for the same process's CPU/disk.
///
/// A plain end-of-function cleanup call would not be enough: a panic (a
/// genuine convergence-divergence failure, the exact thing this test exists
/// to catch) must tear the mesh down too, or the *next* seed inherits it.
/// `Drop` runs during unwinding as well as on a normal return, so
/// constructing this right after the mesh connects and letting it fall out
/// of scope covers both paths uniformly.
struct MeshTeardownGuard {
    session_handles: Vec<tokio::task::JoinHandle<()>>,
    links: Vec<(Arc<DaemonState>, String)>,
}

impl Drop for MeshTeardownGuard {
    fn drop(&mut self) {
        for handle in &self.session_handles {
            handle.abort();
        }
        for (state, local_path) in &self.links {
            link_manager::stop_link_watch(state, local_path);
        }
    }
}

/// Pairs every device with every other over loopback (a full mesh), the
/// direct-transport stand-in for the coordination-driven peer connections
/// the orchestrator would establish for an authorized group. Returns every
/// paired session's `JoinHandle` so the caller can build a
/// [`MeshTeardownGuard`] -- see that type's doc comment for why leaving them
/// running is a real bug, not just tidiness.
#[must_use]
async fn connect_mesh(devices: &[TestDevice], group_id: &str) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();
    let groups = [group_id.to_string()];
    for i in 0..devices.len() {
        for j in (i + 1)..devices.len() {
            let pair_handles = support::connect_two_daemons_with_handles(
                &devices[i].state,
                &devices[i].device_id,
                &devices[j].state,
                &devices[j].device_id,
                &groups,
            )
            .await;
            handles.extend(pair_handles);
        }
    }
    handles
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
            let hash = match std::fs::read(root.join(&name)) {
                Ok(content) => hex::encode(Sha256::digest(&content)),
                // Distinct from a genuinely empty file's hash
                // (`hex::encode(Sha256::digest(b""))`): collapsing a read
                // error (e.g. a materialization rename racing this exact
                // read, or a real "file vanished mid-poll") into "empty"
                // would make an in-flight write look identical to a real
                // zero-byte file, hiding exactly the kind of transient
                // mid-flight state this snapshot exists to distinguish from
                // genuine divergence.
                Err(e) => format!("<read-error: {e}>"),
            };
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

/// Detailed per-device diagnostics for every path that currently differs
/// across `snapshots` (relative to device-0): each device's DAG group heads
/// (do the devices even agree on the same frontier?) plus `describe_index_state`
/// for each affected path. Shared by both the timeout-path context dump
/// below and the final strict-equality check, so a run that times out
/// *inside* `wait_until_with_context` -- never reaching the code after it --
/// still surfaces the same DAG-level diagnostics a slower or CI-only
/// divergence would otherwise only reveal on a later reproduction attempt.
/// Empty when nothing currently differs.
fn diff_diagnostics(
    devices: &[TestDevice],
    group_id: &str,
    snapshots: &[HashMap<String, String>],
) -> String {
    let reference = &snapshots[0];
    let mut affected: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for snap in &snapshots[1..] {
        affected.extend(reference.keys().filter(|k| !snap.contains_key(*k)).cloned());
        affected.extend(snap.keys().filter(|k| !reference.contains_key(*k)).cloned());
        affected.extend(
            reference.keys().filter(|k| snap.get(*k).is_some_and(|v| v != &reference[*k])).cloned(),
        );
    }
    if affected.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (d, device) in devices.iter().enumerate() {
        let heads = match device.state.sync_state.dag_group_heads(group_id) {
            Ok(hs) => hs.iter().map(|h| h.to_hex()).collect::<Vec<_>>(),
            Err(e) => vec![format!("<error reading heads: {e}>")],
        };
        out.push_str(&format!("  device-{d} dag_group_heads={heads:?}\n"));
    }
    for name in &affected {
        for (d, device) in devices.iter().enumerate() {
            out.push_str(&format!(
                "  device-{d} sync_state[{name:?}]: {}\n",
                describe_index_state(&device.state, group_id, name)
            ));
        }
    }
    out
}

async fn run_chaos(seed: u64) {
    let _ = tracing_subscriber::fmt::try_init();
    let coordination_addr = support::start_coordination_server().await;
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
        start_watching(device, &group_id).await;
    }
    let session_handles = connect_mesh(&devices, &group_id).await;
    // Constructed immediately after the mesh connects (before any chaos
    // operation that could panic) and never explicitly dropped early: `Drop`
    // runs whether this function returns normally or panics, so this seed's
    // entire mesh is guaranteed torn down before `replay_known_failing_
    // seeds`'s loop -- or `random_concurrent_operations...`'s own single
    // run -- moves on. See `MeshTeardownGuard`'s doc comment.
    let _mesh_teardown = MeshTeardownGuard {
        session_handles,
        links: devices
            .iter()
            .map(|d| (d.state.clone(), d.root.path().to_string_lossy().into_owned()))
            .collect(),
    };

    // Give peer sessions a moment to establish before the chaos begins.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let candidate_names: Vec<String> =
        (0..CANDIDATE_FILE_COUNT).map(|i| format!("chaos-{i:02}.bin")).collect();

    let mut rng = StdRng::seed_from_u64(seed);
    for round in 0..ROUNDS {
        let device_idx = rng.random_range(0..DEVICE_COUNT);
        let device = &devices[device_idx];
        let name = &candidate_names[rng.random_range(0..CANDIDATE_FILE_COUNT)];
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
        let action = match rng.random_range(0..4) {
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
                let other_name = &candidate_names[rng.random_range(0..CANDIDATE_FILE_COUNT)];
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
        tokio::time::sleep(Duration::from_millis(rng.random_range(10..60))).await;
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
            let replicas_equal = current[1..].iter().all(|snapshot| snapshot == &current[0]);
            if replicas_equal && current == *last_snapshots.borrow() {
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
                if current != *last_snapshots.borrow() {
                    *last_snapshots.borrow_mut() = current;
                }
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
            // peer-mediated conflict resolution) happened to finish
            // later than (deadline - 110s) -- observed causing this exact
            // wait to time out despite all devices already holding
            // byte-identical content at that point, a test-timing false
            // failure, not a real divergence.
            //
            // A much shorter window (30, ~3s) then over-corrected the
            // other way: `debounce::DEFAULT_MAX_FLUSH_INTERVAL` alone is
            // 2s, and this is 4 devices each running their own debounce/
            // executor pair plus real transport round trips and reconciliation
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
            let current: Vec<HashMap<String, String>> =
                devices_ref.iter().map(|d| snapshot(d.root.path())).collect();
            let dump = current
                .iter()
                .enumerate()
                .map(|(i, snap)| format!("device-{i} snapshot={snap:?}"))
                .collect::<Vec<_>>()
                .join("\n");
            // DAG-heads + index-state detail for whatever currently differs.
            // A timeout here means the code after this `.await` (which would
            // otherwise produce this same detail) never runs, so without
            // this the only diagnostic a CI-only timeout leaves behind is
            // raw file content -- not enough to tell a stalled delivery/
            // admission from a materialization determinism bug apart.
            let diag = diff_diagnostics(devices_ref, &group_id, &current);
            format!(
                "stability_reset_count={} (how many times the wait's own stability window \
                 restarted; a large count with names already matching suggests content is \
                 still genuinely changing, not just a slow one-time convergence)\n{dump}\n\
                 --- DAG heads / sync_state detail for currently-differing paths ---\n{diag}",
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
        let index_dump = diff_diagnostics(&devices, &group_id, &final_snapshots);
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
/// `unwrap`, or the final divergence `panic!`) so the seed can be
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
        // Plain stdout, not just `tracing::info!`: a corpus replay failure
        // in ordinary CI output (no RUST_LOG set) previously gave no way to
        // tell which of possibly several corpus seeds actually failed.
        eprintln!(
            "MONKEY_CHAOS replaying corpus seed={seed} (reproduce with: MONKEY_CHAOS_SEED={seed} \
             cargo test -p yadorilink-daemon --test monkey_chaos random_concurrent_operations -- \
             --nocapture)"
        );
        tracing::info!(seed, "replaying corpus seed");
        run_chaos_recording_seed_on_failure(seed).await;
    }
}
