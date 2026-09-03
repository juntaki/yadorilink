//! M2-4: proves the EXISTING, platform-neutral local-change pipeline
//! (`LocalChangeProcessor::scan_existing_files`, the same classification
//! logic a live filesystem watcher's `process_event` uses for a
//! `CreatedOrModified` event) correctly handles real Windows CfAPI
//! placeholders -- no new sync logic, per the M2 roadmap's own M2-4 scope
//! ("prove the common DAG path already handles Windows
//! create/modify/delete, expect no code change needed").
//!
//! Real, non-mocked: uses `WindowsCfApiBackend` (the same real-`CfAPI`
//! harness `windows_cfapi_smoke.rs` uses) to create and hydrate an actual
//! reparse-point placeholder on disk, and a real `ReplicaCoordinator`
//! (whose `LocalMutationStore::inspect_windows_placeholder` impl calls the
//! real `placeholder_inspect_windows::inspect_placeholder`, i.e. a real
//! `CfGetPlaceholderInfo` call) -- not the synthetic fakes
//! `local_change.rs`'s own `#[cfg(all(test, windows))]` unit tests use.
//! Mirrors `yadorilink-local-capture/tests/materialization_local_capture.rs`'s
//! harness shape exactly (same `LocalChangeProcessor::new(...)
//! .scan_existing_files(...)` seam), the closest existing precedent for
//! "construct a real `LocalChangeProcessor` against a real
//! `ReplicaCoordinator` and assert on what one scan classifies".
//!
//! A Codex review of this file's first version caught a false-positive-
//! proof bug worth recording: `build_record_for_created_or_modified`
//! (`local_change.rs`) only calls the real `CfGetPlaceholderInfo`-backed
//! Windows verdict when the row's `materialization_state` is
//! `Placeholder` -- a row already `Hydrated` never reaches that branch at
//! all (there is no production scenario where the daemon re-inspects an
//! already-`Hydrated` row; any write it later observes there is by
//! definition a real edit). The first version of this file's "hydrated
//! content is a self-echo" test set `materialization_state: Hydrated`
//! after hydrating, so it passed on plain byte-comparison alone and would
//! have kept passing even if the real Windows verdict function were
//! broken or never called. Fixed: both the self-echo and the
//! post-hydration-edit tests below now leave the row `Placeholder` after
//! the real `hydrate` call -- the actual scenario M2-2's Windows dirty
//! detection exists for (Explorer's own `FETCH_DATA` populating a
//! placeholder's content while the daemon has not yet observed/committed
//! a `Hydrated` transition for it), which genuinely exercises
//! `CfGetPlaceholderInfo` for both the `Untouched` and `Dirty` verdicts.
//!
//! This is a steady-state classification proof, not a proof that the
//! cross-process create/persist-generation/converge transition itself is
//! race- or crash-safe -- production mints and persists a generation
//! BEFORE `cfapi-host` creates the real placeholder (M2-3a), the reverse
//! order this file's `index_placeholder_row` helper uses (real disk
//! object first, index second, since this test drives `WindowsCfApiBackend`
//! in-process rather than through the real daemon<->cfapi-host poll
//! loop). That transition window is Pass 1/M2-3a's and M2-3c's own
//! concern, not this file's.
#![cfg(windows)]

use std::sync::Arc;

use yadorilink_daemon::placeholder_backend_windows::WindowsCfApiBackend;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::placeholder_backend::PlaceholderBackend;
use yadorilink_local_storage::{
    BlockStore, FsBlockStore, PlaceholderDiskIdentity, WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};
use yadorilink_root_authority::root_identity::VerifiedRoot;

fn unique_temp_root() -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    let nanos =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    dir.push(format!("yadorilink-local-mutation-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn adopt_root(state: &ReplicaCoordinator, group: &str, root: &std::path::Path) {
    let _ = state.link_repository().add_link(&root.to_string_lossy(), group);
    VerifiedRoot::open(root, group, state).unwrap();
}

/// Indexes `path`'s content as the group's current version, records the
/// REAL generation `backend.create`/`.hydrate` minted as this row's
/// placeholder identity (the same `(dev=0, ino=generation)` encoding
/// `WINDOWS_CFAPI_GENERATION_PROVIDER_KIND` uses -- see
/// `yadorilink_local_storage::materialize_write`'s own doc), and sets
/// `materialization_state`. This mirrors what M2-3a's production path
/// (daemon mints, cfapi-host creates, poll converges) eventually leaves
/// the index holding -- reproduced directly here since this test drives
/// `WindowsCfApiBackend` in-process rather than through the real
/// cross-process poll loop.
fn index_placeholder_row(
    state: &ReplicaCoordinator,
    store: &FsBlockStore,
    group: &str,
    path: &str,
    content: &[u8],
    generation: u64,
    materialization_state: MaterializationState,
    permit: &RootCommitPermit,
) {
    let hash = store.put(content).unwrap().into_bytes();
    state
        .file_index_repository()
        .upsert_file(
            group,
            &FileRecord {
                path: path.to_string(),
                size: content.len() as u64,
                mtime_unix_nanos: 1_700_000_000_000_000_000,
                blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
                deleted: false,
            },
            permit,
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(group, path, materialization_state, permit)
        .unwrap();
    state
        .materialization_state_repository()
        .record_placeholder_generation(
            group,
            path,
            PlaceholderDiskIdentity { dev: 0, ino: generation },
            WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
            permit,
        )
        .unwrap();
}

fn processor(
    state: Arc<ReplicaCoordinator>,
    store: Arc<FsBlockStore>,
) -> yadorilink_local_capture::LocalChangeProcessor {
    yadorilink_local_capture::LocalChangeProcessor::new(
        state,
        store,
        "device-a".to_string(),
        Arc::new(RootLease::for_tests()),
    )
}

/// The core M2-4 property: a real `CfCreatePlaceholders` + real `hydrate`
/// (provider-populated, not `std::fs::write`) round trip, observed while
/// the row is still `Placeholder` (the actual self-echo window -- see
/// this file's own top-level doc comment), must be classified as an
/// untouched self-echo by the SAME `scan_existing_files` call the
/// watcher-driven `process_event` path uses -- not re-captured as a
/// fresh local edit. This genuinely exercises `local_change.rs`'s real
/// `CfGetPlaceholderInfo`-backed Windows verdict (`Placeholder` state is
/// the one condition that branch requires), not mere byte comparison.
#[test]
fn hydrated_placeholder_content_is_recognized_as_self_echo_not_a_local_edit() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(block_dir.path()).unwrap());
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = unique_temp_root();
    adopt_root(&state, "group-1", &root);

    let backend = WindowsCfApiBackend::register(&root)
        .expect("CfRegisterSyncRoot should succeed for a fresh local directory");
    let content = b"real placeholder content".to_vec();
    let placeholder_path = root.join("doc.txt");
    let generation = backend
        .create(&placeholder_path, content.len() as u64, 1_700_000_000_000_000_000)
        .expect("CfCreatePlaceholders should succeed")
        .0;
    backend
        .hydrate(&placeholder_path, &mut content.as_slice())
        .expect("hydrate should populate the placeholder and mark it in-sync");

    // Deliberately `Placeholder`, not `Hydrated` -- see this file's own
    // top-level doc comment for why only this state actually reaches the
    // real Windows verdict branch.
    index_placeholder_row(
        &state,
        &store,
        "group-1",
        "doc.txt",
        &content,
        generation,
        MaterializationState::Placeholder,
        &RootCommitPermit::for_tests(),
    );

    let minted =
        processor(state.clone(), store.clone()).scan_existing_files("group-1", &root).unwrap();

    assert!(
        minted.is_empty(),
        "a real CfAPI-hydrated placeholder whose recorded generation matches the live \
         CfGetPlaceholderInfo/in-sync state must be classified as an untouched self-echo, \
         not re-captured: {minted:?}"
    );

    drop(backend);
    if let Err(e) = std::fs::remove_dir_all(&root) {
        eprintln!("warning: failed to clean up test root {}: {e}", root.display());
    }
}

/// The other side of the same property: a REAL local edit made after
/// hydration (a genuine `std::fs::write`, clearing CfAPI's in-sync bit,
/// exactly as `windows_cfapi_smoke.rs`'s own backend-level test performs),
/// still observed while the row is `Placeholder` -- must still be
/// captured through the full `scan_existing_files` path. Proves the
/// self-echo suppression above is not simply "never captures Windows
/// placeholders", but is actually gated on the live in-sync check: this
/// test drives `CfGetPlaceholderInfo` to a real `Dirty` verdict, the
/// same real branch the previous test drives to `Untouched`.
#[test]
fn a_real_local_edit_after_hydration_is_still_captured() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(block_dir.path()).unwrap());
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = unique_temp_root();
    adopt_root(&state, "group-1", &root);

    let backend = WindowsCfApiBackend::register(&root)
        .expect("CfRegisterSyncRoot should succeed for a fresh local directory");
    let content = b"real placeholder content".to_vec();
    let placeholder_path = root.join("doc.txt");
    let generation = backend
        .create(&placeholder_path, content.len() as u64, 1_700_000_000_000_000_000)
        .expect("CfCreatePlaceholders should succeed")
        .0;
    backend
        .hydrate(&placeholder_path, &mut content.as_slice())
        .expect("hydrate should populate the placeholder and mark it in-sync");

    index_placeholder_row(
        &state,
        &store,
        "group-1",
        "doc.txt",
        &content,
        generation,
        MaterializationState::Placeholder,
        &RootCommitPermit::for_tests(),
    );

    // A genuine local edit, same length as the original content -- the
    // exact case a size/mtime-only heuristic would miss, which is why
    // M2-2 replaced it with a live CfAPI in-sync query on Windows. This
    // real write clears CfAPI's in-sync bit, so `CfGetPlaceholderInfo`
    // now genuinely reports `Dirty`.
    std::fs::write(&placeholder_path, b"a real local edit!!!!!!!!").unwrap();

    let minted =
        processor(state.clone(), store.clone()).scan_existing_files("group-1", &root).unwrap();
    let minted_paths: Vec<String> = minted.iter().map(|r| r.path.clone()).collect();

    assert_eq!(
        minted_paths,
        vec!["doc.txt".to_string()],
        "a real edit that clears CfAPI's in-sync bit must be captured as a genuine local \
         change, even though it happens to match the original content's length: {minted:?}"
    );

    drop(backend);
    if let Err(e) = std::fs::remove_dir_all(&root) {
        eprintln!("warning: failed to clean up test root {}: {e}", root.display());
    }
}

/// M2-4's "delete" case, absent from this file's first version (a Codex
/// review finding): a locally deleted, previously-hydrated placeholder
/// must be tombstoned (`FileRecord.deleted == true`) by the SAME
/// `scan_existing_files` reconciliation pass -- `ReconcileMode::Full {
/// emit_tombstones: true }`, `scan_existing_files`'s default -- a live
/// watcher's own `Removed` event handling relies on identically.
#[test]
fn a_locally_deleted_hydrated_placeholder_is_tombstoned() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(block_dir.path()).unwrap());
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = unique_temp_root();
    adopt_root(&state, "group-1", &root);

    let backend = WindowsCfApiBackend::register(&root)
        .expect("CfRegisterSyncRoot should succeed for a fresh local directory");
    let content = b"real placeholder content".to_vec();
    let placeholder_path = root.join("doc.txt");
    let generation = backend
        .create(&placeholder_path, content.len() as u64, 1_700_000_000_000_000_000)
        .expect("CfCreatePlaceholders should succeed")
        .0;
    backend
        .hydrate(&placeholder_path, &mut content.as_slice())
        .expect("hydrate should populate the placeholder and mark it in-sync");

    index_placeholder_row(
        &state,
        &store,
        "group-1",
        "doc.txt",
        &content,
        generation,
        MaterializationState::Placeholder,
        &RootCommitPermit::for_tests(),
    );

    std::fs::remove_file(&placeholder_path).expect("deleting the placeholder must succeed");

    let minted =
        processor(state.clone(), store.clone()).scan_existing_files("group-1", &root).unwrap();

    assert_eq!(
        minted.len(),
        1,
        "exactly one tombstone must be emitted for the deleted path: {minted:?}"
    );
    assert_eq!(minted[0].path, "doc.txt");
    assert!(minted[0].deleted, "the emitted record must be a tombstone (deleted == true)");

    drop(backend);
    if let Err(e) = std::fs::remove_dir_all(&root) {
        eprintln!("warning: failed to clean up test root {}: {e}", root.display());
    }
}

/// A freshly created, never-hydrated placeholder (still fully sparse, no
/// local content at all) must also scan as untouched -- the `Placeholder`
/// materialization-state counterpart to the two `Hydrated`-state tests
/// above.
#[test]
fn a_freshly_created_unhydrated_placeholder_is_recognized_as_untouched() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(block_dir.path()).unwrap());
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = unique_temp_root();
    adopt_root(&state, "group-1", &root);

    let backend = WindowsCfApiBackend::register(&root)
        .expect("CfRegisterSyncRoot should succeed for a fresh local directory");
    let content = b"content pending hydration".to_vec();
    let placeholder_path = root.join("doc.txt");
    let generation = backend
        .create(&placeholder_path, content.len() as u64, 1_700_000_000_000_000_000)
        .expect("CfCreatePlaceholders should succeed")
        .0;

    index_placeholder_row(
        &state,
        &store,
        "group-1",
        "doc.txt",
        &content,
        generation,
        MaterializationState::Placeholder,
        &RootCommitPermit::for_tests(),
    );

    let minted =
        processor(state.clone(), store.clone()).scan_existing_files("group-1", &root).unwrap();

    assert!(
        minted.is_empty(),
        "a freshly created, never-hydrated placeholder must scan as untouched: {minted:?}"
    );

    drop(backend);
    if let Err(e) = std::fs::remove_dir_all(&root) {
        eprintln!("warning: failed to clean up test root {}: {e}", root.display());
    }
}

/// An ordinary file the user created directly (never a CfAPI placeholder
/// at all -- no recorded generation) must be captured normally. Proves
/// the Windows dirty-detection path does not accidentally suppress
/// genuine new files that were never placeholders.
#[test]
fn an_ordinary_new_file_with_no_placeholder_history_is_captured_normally() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(block_dir.path()).unwrap());
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = unique_temp_root();
    adopt_root(&state, "group-1", &root);

    std::fs::write(root.join("new-file.txt"), b"never a placeholder").unwrap();

    let minted =
        processor(state.clone(), store.clone()).scan_existing_files("group-1", &root).unwrap();
    let minted_paths: Vec<String> = minted.iter().map(|r| r.path.clone()).collect();

    assert_eq!(
        minted_paths,
        vec!["new-file.txt".to_string()],
        "a plain new file with no CfAPI history must be captured as a local change: {minted:?}"
    );

    if let Err(e) = std::fs::remove_dir_all(&root) {
        eprintln!("warning: failed to clean up test root {}: {e}", root.display());
    }
}
