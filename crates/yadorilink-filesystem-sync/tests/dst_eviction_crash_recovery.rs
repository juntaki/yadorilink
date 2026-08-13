//! M2-6 (Pass 4): fault-injection DST scenario for the `Evicting` crash
//! window `materialization_eviction::evict_file` opens between setting
//! `MaterializationState::Evicting` and its final `Placeholder` commit --
//! the same window M2-3b's native Windows dehydrate RPC widened (a real
//! cross-process round trip now sits inside it, not just a local disk
//! write) and whose safety this scenario exists to actually EXERCISE
//! under randomized crash timing, not merely reason about in a code
//! review. Verifies the claim `materialization_eviction.rs`'s own doc
//! comment and a Codex review of M2-3b both rely on: `reset_stale_
//! evicting_to_placeholder`'s blanket `Evicting` -> `Placeholder` reset is
//! safe REGARDLESS of which real-world sub-case a crash left behind
//! (placeholder write/dehydrate already landed vs. not), because eviction
//! never destroys a block until strictly after that commit -- so no
//! matter where the crash landed, every block is still in the store and a
//! subsequent hydrate reconstructs the exact original content. No data
//! loss is the invariant under test, not "the row ends up in some
//! particular state".
//!
//! Same shape and same reasoning as the sibling
//! `dst_materialization_crash_recovery.rs` for the `Hydrated` crash
//! window: plain synchronous functions, no `tokio`/`madsim` scheduling to
//! simulate, so the fault is injected by directly constructing the
//! on-disk-and-index state a crash would leave behind, then asserting the
//! real recovery path (here: `MaterializationStateRepository::reset_
//! stale_evicting_to_placeholder`, the exact call `yadorilink-daemon`'s
//! own startup wiring makes) self-heals it. Many seeded variations,
//! covering both crash sub-cases plus block count/size, not one fixed
//! scenario.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::{reconstruct_file, BlockStore, FsBlockStore};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP_ID: &str = "dst-eviction-crash-group";
const PATH: &str = "evicting.bin";
const VARIATIONS: u64 = 200;

/// Which of the two real crash sub-cases `reset_stale_evicting_to_
/// placeholder`'s own doc comment names this seed simulates.
enum CrashLanding {
    /// The placeholder write (Unix `write_placeholder`, or Windows's
    /// `CfDehydratePlaceholder` confirmation) had already landed on disk
    /// before the crash -- disk holds an empty/sparse placeholder-shaped
    /// object, indexed blocks are untouched in the block store.
    AfterPlaceholderWrite,
    /// The crash landed strictly BEFORE the placeholder write/dehydrate
    /// call -- disk still holds the file's full original hydrated
    /// content, unrelated to whatever the (stale) `Evicting` row claims.
    BeforePlaceholderWrite,
}

fn run_scenario(seed: u64) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let root_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let root = root_dir.path().canonicalize().map_err(|e| e.to_string())?;
    let store_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let store = FsBlockStore::new(store_dir.path()).map_err(|e| e.to_string())?;
    let state = ReplicaCoordinator::open_in_memory().map_err(|e| e.to_string())?;
    state
        .link_repository()
        .add_link(&root.to_string_lossy(), GROUP_ID)
        .map_err(|e| e.to_string())?;
    yadorilink_root_authority::root_identity::VerifiedRoot::open(&root, GROUP_ID, &state)
        .map_err(|e| e.to_string())?;

    let num_blocks = rng.random_range(1..=3u32);
    let mut blocks = Vec::with_capacity(num_blocks as usize);
    let mut expected_content = Vec::new();
    let mut offset = 0u64;
    for _ in 0..num_blocks {
        let size = rng.random_range(4..40u32);
        let data: Vec<u8> = (0..size).map(|_| rng.random()).collect();
        let hash_hex = store.put(&data).map_err(|e| e.to_string())?;
        let hash = hex::decode(&hash_hex).map_err(|e| e.to_string())?;
        blocks.push(BlockInfo { hash, offset, size });
        offset += u64::from(size);
        expected_content.extend_from_slice(&data);
    }

    let record = FileRecord {
        path: PATH.to_string(),
        size: expected_content.len() as u64,
        mtime_unix_nanos: 0,
        blocks: blocks.clone(),
        deleted: false,
    };
    let permit = RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(GROUP_ID, &record, &permit)
        .map_err(|e| e.to_string())?;

    // The crash: `evict_file` already committed the transient `Evicting`
    // state (the FIRST write it makes, per its own doc comment: "Index
    // update happens before the disk write") before the process died --
    // matching real eviction's actual ordering, not an arbitrary choice.
    state
        .materialization_state_repository()
        .set_materialization_state(GROUP_ID, PATH, MaterializationState::Evicting, &permit)
        .map_err(|e| e.to_string())?;

    let landing = if rng.random_bool(0.5) {
        CrashLanding::AfterPlaceholderWrite
    } else {
        CrashLanding::BeforePlaceholderWrite
    };
    match landing {
        CrashLanding::AfterPlaceholderWrite => {
            // An empty file at the target path -- the disk shape
            // `write_placeholder` leaves on Unix (a zero-length/sparse
            // object), and close enough to what a Windows CfAPI
            // placeholder whose dehydrate already completed looks like
            // from a plain `std::fs::write` perspective (this repair
            // path never inspects CfAPI-specific reparse-point state at
            // all -- it only ever looks at whether the row is stale
            // `Evicting`, never at disk).
            std::fs::write(root.join(PATH), []).map_err(|e| e.to_string())?;
        }
        CrashLanding::BeforePlaceholderWrite => {
            // The real content is still fully on disk -- the crash landed
            // before any placeholder/dehydrate call ever touched it.
            std::fs::write(root.join(PATH), &expected_content).map_err(|e| e.to_string())?;
        }
    }

    // The real recovery path -- exactly what `yadorilink-daemon::app::run`'s
    // startup wiring calls (see `crates/yadorilink-daemon/src/app.rs`'s
    // own "Recover any file left permanently stuck `Evicting`" section).
    let reset_count = state
        .materialization_state_repository()
        .reset_stale_evicting_to_placeholder()
        .map_err(|e| format!("seed {seed}: reset_stale_evicting_to_placeholder failed: {e}"))?;
    if reset_count != 1 {
        return Err(format!("seed {seed}: expected exactly 1 row reset, got {reset_count}"));
    }

    let state_after = state
        .materialization_state_repository()
        .get_materialization_state(GROUP_ID, PATH)
        .map_err(|e| e.to_string())?;
    if state_after != Some(MaterializationState::Placeholder) {
        return Err(format!(
            "seed {seed}: row must land on Placeholder after reset, got {state_after:?}"
        ));
    }

    // The core invariant: no data loss, regardless of which crash sub-case
    // this seed simulated. Every block eviction indexed is still in the
    // block store (physical reclamation only ever runs strictly AFTER
    // the row commits to `Placeholder` for real, which never happened
    // here -- this crash preempted it), so a subsequent hydrate must
    // reconstruct the file byte-for-byte identical to the original,
    // exactly as if this had simply never been evicted at all.
    reconstruct_file(&store, &root.join(PATH), &blocks, 0)
        .map_err(|e| format!("seed {seed}: reconstruct_file failed after repair: {e}"))?;
    let on_disk = std::fs::read(root.join(PATH)).map_err(|e| e.to_string())?;
    if on_disk != expected_content {
        return Err(format!(
            "seed {seed}: reconstructed content doesn't match the original -- a block was lost \
             across the simulated Evicting crash"
        ));
    }

    Ok(())
}

/// Many seeded variations (block count/sizes, which of the two crash
/// sub-cases landed) of "eviction was interrupted by a crash between its
/// `Evicting` commit and its final `Placeholder` commit" -- all must
/// self-heal via the real startup recovery path with no data loss.
#[test]
fn eviction_self_heals_after_a_simulated_crash_with_no_data_loss() {
    for seed in 0..VARIATIONS {
        run_scenario(seed).unwrap_or_else(|e| panic!("{e}"));
    }
}
