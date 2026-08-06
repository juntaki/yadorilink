//! Originally relocated from `materialization.rs`'s own internal `#[cfg(test)]
//! mod tests` in Phase 7D-8.6 (`LocalChangeProcessor`'s move to
//! `yadorilink-local-capture`), then moved again from
//! `yadorilink-sync-core/tests/` to this crate's own `tests/` in Phase
//! 7D-10.4 (real test migration) — its subject is `LocalChangeProcessor`'s
//! scan behavior at the seam right after a repair, so it belongs beside the
//! crate that owns `LocalChangeProcessor`, not the crate that used to host
//! its fixtures.
//!
//! This is the one materialization test that constructs a real
//! `LocalChangeProcessor` (per the phase 7D-8 ledger's own consumer survey,
//! `materialization.rs`'s test module had exactly one such fixture). It
//! cannot be an internal `yadorilink-local-capture` unit test for the same
//! type-identity reason `86efa7e1`'s `peer_session.rs` relocation and this
//! file's own prior sync-core-hosted incarnation needed to be external: a
//! value built *inside* an internal `#[cfg(test)]` module cannot coerce to
//! `Arc<dyn LocalMutationStore>`/`&dyn MaterializationExecutionPort` across a
//! different compilation of the crate that implements the trait than the one
//! this file itself links against. An external integration test links
//! `yadorilink-daemon` (which owns `ReplicaCoordinator`'s port impls) as an
//! ordinary dev-dependency, the same build this crate's own library code
//! sees, so the coercion is sound here.
//!
//! Phase 7D-10 (sync-core deletion): repointed from `yadorilink_sync_core::
//! index::SyncState` to `yadorilink_daemon::replica_coordinator::
//! ReplicaCoordinator`, this crate's own dev-only back-edge onto
//! `yadorilink-daemon` (mirrors `local_change.rs`'s own tests, repointed the
//! same way).
//!
//! `repair_interrupted_materializations` itself is `yadorilink-filesystem-sync`-owned
//! (reached here through `yadorilink-sync-core`'s re-export shim, the same
//! path this crate's own production code already uses for
//! `debounce`/`watcher`) — this test's real subject is the boundary right
//! after that repair, not the repair implementation itself: it asserts that
//! `LocalChangeProcessor::scan_existing_files` treats the repaired file as a
//! self-echo and neither propagates nor corrects a dropped exec bit. That
//! assertion is about `LocalChangeProcessor`'s behavior, so this crate is its
//! home, not `yadorilink-filesystem-sync`.
//!
//! The three tiny private helpers this test used
//! (`materialization.rs::tests::{adopt_root, crashed_executable,
//! disk_exec_bit}`) are not `pub`, so they are reproduced here directly
//! rather than widened — each is a few lines with no logic of its own
//! worth sharing.

#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations;
use yadorilink_local_storage::{BlockStore, FsBlockStore};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};
use yadorilink_root_authority::root_identity::VerifiedRoot;

fn adopt_root(state: &ReplicaCoordinator, group: &str, root: &std::path::Path) {
    let _ = state.link_repository().add_link(&root.to_string_lossy(), group);
    VerifiedRoot::open(root, group, state).unwrap();
}

fn record_with_blocks(path: &str, content: &[u8], hash: Vec<u8>) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size: content.len() as u64,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
        deleted: false,
    }
}

/// Indexes `path` as a `Hydrated` executable whose blocks are all in the
/// store but whose file is missing, with the materialization intent a crash
/// mid-write leaves behind — the exact state repair reconstructs from.
fn crashed_executable(
    state: &ReplicaCoordinator,
    store: &FsBlockStore,
    path: &str,
    content: &[u8],
) {
    let hash = hex::decode(store.put(content).unwrap()).unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &record_with_blocks(path, content, hash),
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .set_exec_bit("group-1", path, true, &RootCommitPermit::for_tests())
        .unwrap();
    state
        .materialization_job_repository()
        .begin_materialization_intent("group-1", path, &[0u8; 32], &RootCommitPermit::for_tests())
        .unwrap();
}

fn disk_exec_bit(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o100 != 0
}

/// End-to-end over the seam that decides how bad a dropped exec bit is: a
/// repair followed by the startup scan the daemon runs next.
///
/// `reconstruct_file_journaled`'s own `apply_exec_bit` call (right after the
/// reconstruct) already reapplies the index's recorded exec bit to the
/// repaired file, so by the time the scan runs, disk and index already agree
/// — the scan mints nothing to report either way, and this test asserts that
/// agreement holds across it. `reconstruct_file` also now stamps the
/// repaired file's on-disk mtime to the indexed `mtime_unix_nanos` (0 here),
/// so the scan's size+mtime fast path fires directly rather than falling
/// through to the slower full chunk-and-compare self-echo path; either path
/// reaches the same "nothing changed" verdict once exec bit already agrees,
/// so this is not itself part of what the assertions below check.
#[test]
fn repair_leaves_disk_exec_bit_agreeing_with_the_index_across_a_scan() {
    let block_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(block_dir.path()).unwrap());
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, "group-1", root.path());
    crashed_executable(&state, &store, "tool.sh", b"#!/bin/sh\necho hello\n");

    let report = repair_interrupted_materializations(
        state.as_ref(),
        store.as_ref(),
        root.path(),
        "group-1",
        &RootCommitPermit::for_tests(),
    )
    .unwrap();
    assert_eq!(report.reconstructed, vec!["tool.sh".to_string()]);

    let minted = yadorilink_local_capture::LocalChangeProcessor::new(
        state.clone(),
        store.clone(),
        "device-a".to_string(),
        Arc::new(RootLease::for_tests()),
    )
    .scan_existing_files("group-1", root.path())
    .unwrap();

    assert!(
        minted.is_empty(),
        "the scan suppresses the repaired file as a self-echo, so it can neither propagate \
         a dropped exec bit nor repair one: {minted:?}"
    );
    assert!(
        state.file_index_repository().get_exec_bit("group-1", "tool.sh").unwrap(),
        "the index keeps exec_bit=true across the scan"
    );
    assert!(
        disk_exec_bit(&root.path().join("tool.sh")),
        "so the disk must already agree with it -- no later pass reconciles the two"
    );
}
