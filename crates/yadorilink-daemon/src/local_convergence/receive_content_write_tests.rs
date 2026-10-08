//! A peer's file content written here end to end: an empty file, a file of
//! one block and a file of several, each proven exactly once its bytes are
//! durable; and a write whose path is touched after its pre-write commit,
//! which must publish nothing.

use std::collections::BTreeSet;
use std::sync::Arc;

use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::MaterializationState;

use super::growing_file_projection_tests::{Harness, GROUP};
use crate::test_support::remote_admission_fixture::{admit_remote, put};

/// Captures `content` under a scratch name and admits a peer's put of that
/// same version at `name`, so the blocks are this group's and `name` has no
/// row yet: what a fresh receive looks like once its fetch is done.
async fn admit_received(h: &Harness, name: &str, content: &[u8]) -> FileVersion {
    let source = format!("source-{name}");
    std::fs::write(h.path(&source), content).unwrap();
    assert!(matches!(h.capture(&source).await, LocalChangeOutcome::FileChanged(_)));
    let version = VersionHash(h.own_head(&source).content.unwrap().version_hash);
    let stored = h.state.dag_get_file_version(GROUP, &version).unwrap().expect("stored here");
    admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put(name, version, vec![])],
        std::slice::from_ref(&stored),
    );
    stored
}

async fn project(h: &Harness, name: &str) {
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from([name.to_owned()]))
        .await;
}

/// The version the published proof at `name` names, if one is current.
fn proven_version(h: &Harness, name: &str) -> Option<VersionHash> {
    h.state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::materialized_generation::lookup_materialized_generation(
                conn, GROUP, name,
            )
        })
        .unwrap()
        .and_then(|basis| basis.version)
}

async fn receive_and_prove(content: &[u8], expect_blocks: std::ops::RangeInclusive<usize>) {
    let h = Harness::new(false);
    let version = admit_received(&h, "received.bin", content).await;
    assert!(
        expect_blocks.contains(&version.blocks.len()),
        "fixture: {} blocks",
        version.blocks.len()
    );

    project(&h, "received.bin").await;

    assert_eq!(std::fs::read(h.path("received.bin")).unwrap(), content, "exact bytes on disk");
    assert_eq!(
        h.state.get_materialization_state(GROUP, "received.bin").unwrap(),
        Some(MaterializationState::Present)
    );
    assert_eq!(proven_version(&h, "received.bin"), Some(version.version_hash), "exact proof");
    assert!(
        !h.state.has_materialization_intent(GROUP, "received.bin").unwrap(),
        "the proof's commit clears the intent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_file_is_received_and_proven() {
    receive_and_prove(b"", 0..=0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_block_file_is_received_and_proven() {
    receive_and_prove(b"one small block of a peer's file", 1..=1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_multi_block_file_is_received_and_proven() {
    let block = yadorilink_local_storage::chunker::DEFAULT_BLOCK_SIZE;
    let content: Vec<u8> = (0..2 * block + 1000).map(|i| (i % 251) as u8).collect();
    receive_and_prove(&content, 2..=usize::MAX).await;
}

/// What a write touched after its pre-write commit leaves: no proof, the
/// row still in flight, the intent still open, so a later pass re-drives it.
fn assert_published_nothing(h: &Harness, name: &str, context: &str) {
    assert_eq!(proven_version(h, name), None, "{context}: no proof is published");
    assert_ne!(
        h.state.get_materialization_state(GROUP, name).unwrap(),
        Some(MaterializationState::Present),
        "{context}: the row does not claim the bytes"
    );
    assert!(
        h.state.has_materialization_intent(GROUP, name).unwrap(),
        "{context}: the intent stays open, so the write is re-driven"
    );
}

/// A capture or any other mutator of the path bumps its fence after the
/// write's pre-write commit and before its proof: the proof's CAS is on the
/// value that commit bumped, so it must fail. The bytes on disk at that
/// moment may already be someone else's to describe.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fence_moved_after_the_pre_write_commit_makes_the_proof_publish_nothing() {
    let h = Harness::new(false);
    let content = b"bytes whose proof loses its fence";
    admit_received(&h, "raced.bin", content).await;
    let state = h.state.clone();
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() = Some(Box::new(move |_| {
        state.dag_bump_mutation_fence(GROUP, "raced.bin", "local_capture").unwrap();
    }));

    project(&h, "raced.bin").await;

    assert_published_nothing(&h, "raced.bin", "fence moved");
}

/// A local save lands on the path after the pre-write commit and before the
/// rename: it is kept, and nothing is proven for the peer's bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_edit_after_the_pre_write_commit_is_kept_and_publishes_nothing() {
    let h = Harness::new(false);
    admit_received(&h, "edited.bin", b"the peer's bytes").await;
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() =
        Some(Box::new(|out_path| std::fs::write(out_path, b"saved locally meanwhile").unwrap()));

    project(&h, "edited.bin").await;

    assert_eq!(std::fs::read(h.path("edited.bin")).unwrap(), b"saved locally meanwhile");
    assert_published_nothing(&h, "edited.bin", "local edit");
}
