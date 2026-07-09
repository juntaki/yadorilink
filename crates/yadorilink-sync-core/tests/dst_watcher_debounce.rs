//! Deterministic simulation testing (DST) harness skeleton
//! (add-deterministic-sync-testing task group 3): runs the real
//! watcher-boundary/debounce/local-change-indexing code (unmodified in
//! its logic) under `madsim`'s simulated, seed-controlled scheduler,
//! substituting `watcher::SimulatedFolderWatchSource` for a real OS
//! watcher (see that type's doc comment for why the watcher specifically
//! needs a manual substitute while everything downstream of it does
//! not).
//!
//! Only compiled/run when built with `RUSTFLAGS="--cfg madsim"` (the
//! whole point is exercising the simulated scheduler) — a plain
//! `cargo test` never builds this file at all.
//!
//! `run_many_seeded_variations_in_parallel` is this skeleton's actual
//! scenario: it doesn't stop at "one seed, one scenario" but drives many
//! independently-seeded simulated runs concurrently across OS threads,
//! each fully isolated (its own `madsim::runtime::Runtime`) and fully
//! reproducible from its own seed — the intended day-to-day shape of
//! this harness, not just a smoke test of the plumbing.

#![cfg(madsim)]

mod dst_support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use yadorilink_local_storage::FsBlockStore;
use yadorilink_sync_core::debounce::{self, DebounceConfig};
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::local_change::LocalChangeProcessor;
use yadorilink_sync_core::watcher::{
    FolderWatchSource, FsChangeEvent, FsChangeKind, SimulatedFolderWatchSource,
};

use dst_support::{check_no_silent_data_loss, format_violations, WriteOracle};

const GROUP_ID: &str = "dst-group";
const DEVICE_ID: &str = "dst-device";
const OPS_PER_RUN: usize = 15;
/// Default seed count for a plain `cargo test` run — deliberately larger
/// than a quick smoke check now that each run is known-cheap (~ms) and
/// the point of a chaos/DST-style test is exploring many interleavings,
/// not confirming the plumbing works once. Override with `DST_VARIATIONS`
/// for a per-PR-sized fast run or a much larger heat-run/nightly sweep.
const PARALLEL_VARIATIONS: usize = 500;

/// One seeded, fully deterministic simulated run: performs
/// `OPS_PER_RUN` randomized local writes through the real watcher-event
/// boundary -> debounce -> `LocalChangeProcessor` indexing pipeline
/// (`link_manager::start_link_watch_with_source`'s production wiring,
/// reproduced directly against `yadorilink-sync-core` here since that
/// production entry point lives in `yadorilink-daemon`, whose coordination-
/// plane dependency isn't part of this change's madsim scope -- see
/// design.md's Non-Goals), then asserts the shared no-silent-data-loss
/// invariant checker (`dst_support::check_no_silent_data_loss`, design.md
/// D3) finds no violation.
fn run_scenario(seed: u64) -> Result<(), String> {
    let mut rt = madsim::runtime::Runtime::with_seed_and_config(seed, madsim::Config::default());
    rt.set_time_limit(Duration::from_secs(60));
    // r2d2 (SyncState's sqlite connection pool) spawns a real background
    // maintenance thread -- unrelated to the scheduling determinism this
    // harness cares about (disk/DB determinism is deferred to task 6.1's
    // `MaterializeIo`, see design.md D2), so allow it rather than
    // reimplementing connection pooling to avoid a background thread.
    rt.set_allow_system_thread(true);
    rt.block_on(scenario_body(seed))
}

async fn scenario_body(seed: u64) -> Result<(), String> {
    let root_dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    // Canonicalize up front, matching what the real `watch_folder`
    // does to `root` internally (see watcher.rs's own tests for the
    // same note) -- macOS's tempdir lives under a `/var` path that's
    // itself a symlink to `/private/var`, so path-prefix stripping
    // during indexing would otherwise silently mismatch.
    let root: PathBuf = root_dir.path().canonicalize().map_err(|e| format!("canonicalize: {e}"))?;
    let store_dir = tempfile::tempdir().map_err(|e| format!("store tempdir: {e}"))?;
    let store =
        Arc::new(FsBlockStore::new(store_dir.path()).map_err(|e| format!("block store: {e}"))?);
    let sync_state = Arc::new(SyncState::open_in_memory().map_err(|e| format!("sync state: {e}"))?);
    sync_state.add_link(&root.to_string_lossy(), GROUP_ID).map_err(|e| format!("add_link: {e}"))?;
    let processor =
        LocalChangeProcessor::new(sync_state.clone(), store.clone(), DEVICE_ID.to_string());

    let (watch_source, events_tx) = SimulatedFolderWatchSource::new(64);
    let ignore_set =
        Arc::new(yadorilink_sync_core::ignore_patterns::EffectiveIgnoreSet::defaults_only());
    let watcher = watch_source.watch(&root, ignore_set).map_err(|e| format!("watch: {e}"))?;
    let (events_rx, overflowed, _guard) = watcher.split();

    let (flush_tx, mut flush_rx) =
        tokio::sync::mpsc::channel(debounce::DEFAULT_EXECUTOR_CHANNEL_CAPACITY);
    let (_flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    let (_flush_all_request_tx, flush_all_request_rx) = tokio::sync::mpsc::channel(4);

    tokio::spawn(debounce::run_debouncer(
        DebounceConfig::default(),
        events_rx,
        flush_tx,
        overflowed,
        flush_request_rx,
        flush_all_request_rx,
    ));

    let executor_processor = processor;
    let executor_root = root.clone();
    let executor = tokio::spawn(async move {
        while let Some(flush) = flush_rx.recv().await {
            if let Err(e) = executor_processor.process_flush(GROUP_ID, &executor_root, flush).await
            {
                tracing::warn!(error = %e, "dst scenario: process_flush failed");
            }
        }
    });

    let mut rng = StdRng::seed_from_u64(seed);
    let oracle = WriteOracle::new();
    let candidate_names: Vec<String> = (0..6).map(|i| format!("dst-{i:02}.bin")).collect();

    for round in 0..OPS_PER_RUN {
        let name = &candidate_names[rng.gen_range(0..candidate_names.len())];
        let path = root.join(name);
        let content = format!("seed {seed} round {round} name {name}");
        std::fs::write(&path, content.as_bytes()).map_err(|e| format!("write: {e}"))?;
        oracle.record_write(name, content.as_bytes());

        // The scenario controls exactly when the synthetic watcher event
        // is delivered relative to the real write above -- a randomized
        // simulated delay here is what makes different seeds actually
        // explore different debounce-window interleavings, unlike a real
        // OS watcher whose timing this process doesn't control.
        let delay_ms = rng.gen_range(0..40);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        events_tx
            .send(FsChangeEvent { path, kind: FsChangeKind::CreatedOrModified })
            .await
            .map_err(|_| "events channel closed early".to_string())?;
    }

    // Give the last window's own quiet period/max-flush-interval room to
    // fire under simulated time (fast-forwarded, not a real wall-clock
    // wait) before checking the index.
    tokio::time::sleep(DebounceConfig::default().max_flush_interval + Duration::from_millis(200))
        .await;
    drop(events_tx);
    let _ = executor.await;

    let violations = check_no_silent_data_loss(&oracle, &sync_state, GROUP_ID, &root);
    if !violations.is_empty() {
        return Err(format_violations(seed, &violations));
    }
    Ok(())
}

/// The harness's actual day-to-day shape: not one seed, but many
/// independently-seeded runs driven concurrently, each fully isolated
/// and fully reproducible on its own. A failure reports its seed so it
/// can be re-run in isolation (`DST_SEED=<seed> cargo test ...
/// single_seed_smoke`, or `run_scenario(seed)` directly) to reproduce.
///
/// `DST_VARIATIONS` overrides how many seeds this run explores (default
/// `PARALLEL_VARIATIONS`) — a small fixed count is enough for a fast
/// per-PR check, a much larger one (thousands) for a heat-run/nightly
/// sweep (design.md's task 7 CI-vs-heat-run split); each simulated run
/// costs low-single-digit milliseconds since simulated time is
/// fast-forwarded, so scaling this up is cheap. Bounded to
/// `available_parallelism` concurrent OS threads (a shared work queue,
/// not one real thread per seed) so a large `DST_VARIATIONS` doesn't
/// spawn thousands of real threads at once.
#[test]
fn run_many_seeded_variations_in_parallel() {
    let base_seed: u64 =
        std::env::var("DST_BASE_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0xD57_0000);
    let variations: u64 = std::env::var("DST_VARIATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(PARALLEL_VARIATIONS as u64);
    let worker_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(usize::try_from(variations).unwrap_or(usize::MAX).max(1));

    let next_index = AtomicU64::new(0);
    let failures: Mutex<Vec<String>> = Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            scope.spawn(|| loop {
                let i = next_index.fetch_add(1, Ordering::Relaxed);
                if i >= variations {
                    break;
                }
                let seed = base_seed.wrapping_add(i);
                if let Err(err) = run_scenario(seed) {
                    failures
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .push(format!("seed {seed}: {err}"));
                }
            });
        }
    });

    let failures = failures.into_inner().unwrap_or_else(|p| p.into_inner());
    assert!(
        failures.is_empty(),
        "{}/{variations} DST variations failed:\n{}\n(reproduce one with DST_SEED=<seed> cargo test ... single_seed_smoke, or call run_scenario(seed) directly)",
        failures.len(),
        failures.join("\n")
    );
}

/// Single-seed entry point for reproducing a specific failure reported by
/// `run_many_seeded_variations_in_parallel` above.
#[test]
fn single_seed_smoke() {
    let seed: u64 = std::env::var("DST_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    run_scenario(seed).unwrap_or_else(|e| panic!("seed {seed} failed: {e}"));
}
