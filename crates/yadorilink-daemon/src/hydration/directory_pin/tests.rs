#![cfg(test)]

//! A folder asked for through the materialization port is a policy over
//! what is below it: pinned now and later, released by its own unpin or
//! eviction, and never silently unpinned out from under a pinned folder
//! above it.

use std::sync::Arc;

use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::adapters::runtime::materialization::DaemonMaterializationAdapter;
use crate::application::ports::{MaterializationPort, MaterializationStateSummary};
use crate::daemon_state::DaemonState;
use crate::sync_error::SyncError;

const GROUP: &str = "group-1";

fn state_with_link() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let coordinator =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    coordinator.link_repository().add_link("/home/alice/Photos", GROUP).unwrap();
    DaemonState::new("device-a".into(), coordinator, store)
}

fn file(state: &DaemonState, path: &str, materialization: MaterializationState) {
    let permit = RootCommitPermit::for_tests();
    let coordinator = &state.replica_coordinator;
    coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: path.into(),
                size: 10,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, path, materialization, &permit)
        .unwrap();
}

#[tokio::test]
async fn pinning_a_folder_pins_what_is_below_it_until_it_is_unpinned() {
    let state = state_with_link();
    file(&state, "trips/2026/beach.jpg", MaterializationState::Hydrated);
    file(&state, "trips/notes.txt", MaterializationState::Hydrated);
    file(&state, "loose.txt", MaterializationState::Hydrated);
    let port = DaemonMaterializationAdapter::new(state.clone());
    let index = state.replica_coordinator.file_index_repository();

    port.pin(GROUP, "trips").await.unwrap();
    assert!(index.is_pinned(GROUP, "trips/2026/beach.jpg").unwrap());
    assert!(index.is_pinned(GROUP, "trips/notes.txt").unwrap());
    assert!(!index.is_pinned(GROUP, "loose.txt").unwrap());
    // A file that arrives below the folder later is pinned too.
    file(&state, "trips/2026/later.jpg", MaterializationState::Placeholder);
    assert!(index.is_pinned(GROUP, "trips/2026/later.jpg").unwrap());

    let status = port.status(GROUP, "trips/").unwrap().expect("a folder has a status");
    assert!(status.pinned);
    assert_eq!(status.state, MaterializationStateSummary::Placeholder);
    let sub = port.status(GROUP, "trips/2026").unwrap().unwrap();
    assert!(sub.pinned, "a folder below a pinned folder is pinned");

    // Unpinning what the pinned folder keeps would change nothing.
    for path in ["trips/notes.txt", "trips/2026"] {
        let refused = port.unpin(GROUP, path).await.unwrap_err();
        assert!(matches!(refused, SyncError::InvalidInput(_)), "{path}: {refused}");
        assert!(refused.to_string().contains("trips"), "{refused}");
    }

    port.unpin(GROUP, "trips").await.unwrap();
    assert!(!index.is_pinned(GROUP, "trips/notes.txt").unwrap());
    assert!(!port.status(GROUP, "trips").unwrap().unwrap().pinned);
}

/// The link root is a folder too.
#[tokio::test]
async fn the_link_root_can_be_pinned() {
    let state = state_with_link();
    file(&state, "a.txt", MaterializationState::Hydrated);
    let port = DaemonMaterializationAdapter::new(state.clone());
    port.pin(GROUP, "").await.unwrap();
    assert!(state.replica_coordinator.file_index_repository().is_pinned(GROUP, "a.txt").unwrap());
    let status = port.status(GROUP, "").unwrap().unwrap();
    assert!(status.pinned);
    assert_eq!(status.state, MaterializationStateSummary::Hydrated);
}

/// An eviction refused before it starts -- no placeholder pipeline here,
/// or a pinned folder above -- leaves the folder's own pin in place.
#[tokio::test]
async fn a_refused_folder_eviction_changes_nothing() {
    let state = state_with_link();
    file(&state, "trips/beach.jpg", MaterializationState::Hydrated);
    let port = DaemonMaterializationAdapter::new(state.clone());
    port.pin(GROUP, "trips").await.unwrap();

    state.set_test_placeholder_pipeline_connected(false);
    assert!(matches!(port.evict(GROUP, "trips"), Err(SyncError::EvictionRejected(_))));
    assert!(port.status(GROUP, "trips").unwrap().unwrap().pinned);

    state.set_test_placeholder_pipeline_connected(true);
    port.pin(GROUP, "").await.unwrap();
    assert!(matches!(port.evict(GROUP, "trips"), Err(SyncError::InvalidInput(_))));
    let index = state.replica_coordinator.file_index_repository();
    assert_eq!(
        index.pinned_directory_above(GROUP, "trips/beach.jpg").unwrap().as_deref(),
        Some("trips")
    );
}

/// Evicting a folder releases its pin even when nothing below it could be
/// freed.
#[tokio::test]
async fn evicting_a_folder_releases_its_pin() {
    let state = state_with_link();
    file(&state, "trips/beach.jpg", MaterializationState::Placeholder);
    let port = DaemonMaterializationAdapter::new(state.clone());
    state.set_test_placeholder_pipeline_connected(true);
    // Set directly: pinning through the port would first try to fetch the
    // placeholder, and there is no peer here.
    state
        .replica_coordinator
        .file_index_repository()
        .set_directory_pinned(GROUP, "trips", true)
        .unwrap();
    let outcome = port.evict(GROUP, "trips").unwrap();
    assert!(!outcome.dehydrated, "nothing below it was hydrated");
    assert!(!port.status(GROUP, "trips").unwrap().unwrap().pinned);
}

fn delete(state: &DaemonState, path: &str) {
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: path.into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: true,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
}

/// A pinned folder deleted and replaced by a file of the same name: the
/// file is not kept by the old folder's policy, and unpinning the name
/// releases that policy rather than reporting success while it stays.
#[tokio::test]
async fn a_file_that_replaces_a_pinned_folder_is_not_pinned_by_it() {
    let state = state_with_link();
    file(&state, "docs/a.txt", MaterializationState::Hydrated);
    let port = DaemonMaterializationAdapter::new(state.clone());
    port.pin(GROUP, "docs").await.unwrap();
    delete(&state, "docs/a.txt");
    file(&state, "docs", MaterializationState::Hydrated);
    let index = state.replica_coordinator.file_index_repository();

    assert!(!index.is_pinned(GROUP, "docs").unwrap());
    assert!(!port.status(GROUP, "docs").unwrap().unwrap().pinned);

    port.unpin(GROUP, "docs").await.unwrap();
    assert!(!index.is_directory_pinned(GROUP, "docs").unwrap(), "the old policy is released");
}

/// A pinned folder renamed away leaves its policy on the old name, where
/// a later folder of that name would be pinned too. Unpinning the old name
/// removes it even though nothing is there any more.
#[tokio::test]
async fn the_pin_left_on_a_renamed_folders_old_name_can_be_removed() {
    let state = state_with_link();
    file(&state, "Projects/old/a.txt", MaterializationState::Hydrated);
    let port = DaemonMaterializationAdapter::new(state.clone());
    port.pin(GROUP, "Projects/old").await.unwrap();
    delete(&state, "Projects/old/a.txt");
    file(&state, "Projects/archive/a.txt", MaterializationState::Hydrated);
    let index = state.replica_coordinator.file_index_repository();

    port.unpin(GROUP, "Projects/old").await.unwrap();
    file(&state, "Projects/old/new.txt", MaterializationState::Placeholder);
    assert!(!index.is_pinned(GROUP, "Projects/old/new.txt").unwrap());

    // Nothing there and no policy: still not found.
    let missing = port.unpin(GROUP, "Projects/never").await.unwrap_err();
    assert!(matches!(missing, SyncError::NotFound(_)), "{missing}");
}

fn freed(bytes: u64) -> Result<super::FileEviction, SyncError> {
    Ok(super::FileEviction { dehydrated: true, blocks_reclaimed: 1, bytes_reclaimed: bytes })
}

fn left_as_it_was() -> Result<super::FileEviction, SyncError> {
    Ok(super::FileEviction { dehydrated: false, blocks_reclaimed: 0, bytes_reclaimed: 0 })
}

/// A folder eviction that frees some files but not others reports the
/// files that stayed instead of a plain success; one that frees all of
/// them, or leaves every file as it was without a failure, is the sum.
#[test]
fn a_partly_freed_folder_is_reported_as_such() {
    use super::fold_directory_eviction as fold;
    let attempts = |list: Vec<(&str, Result<super::FileEviction, SyncError>)>| {
        list.into_iter().map(|(p, r)| (p.to_string(), r)).collect::<Vec<_>>()
    };

    let all = fold("trips", attempts(vec![("trips/a", freed(5)), ("trips/b", freed(7))])).unwrap();
    assert_eq!((all.evicted_files, all.bytes_reclaimed), (2, 12));

    let none = fold("trips", attempts(vec![("trips/a", left_as_it_was())])).unwrap();
    assert_eq!(none.evicted_files, 0);

    let busy = SyncError::EvictionRejected("trips/b: busy".into());
    let partial = fold(
        "trips",
        attempts(vec![
            ("trips/a", freed(5)),
            ("trips/b", Err(busy)),
            ("trips/c", left_as_it_was()),
        ]),
    )
    .unwrap_err();
    let text = partial.to_string();
    assert!(matches!(partial, SyncError::EvictionRejected(_)), "{text}");
    assert!(text.contains("2 of 3 files stayed"), "{text}");
    assert!(text.contains("1 freed, 5 bytes"), "{text}");
    assert!(text.contains("trips/b"), "{text}");

    let changed =
        fold("trips", attempts(vec![("trips/a", freed(5)), ("trips/c", left_as_it_was())]))
            .unwrap_err();
    assert!(changed.to_string().contains("trips/c was busy or changed"), "{changed}");

    let only_failure = SyncError::NotFound("trips/a".into());
    let failed = fold("trips", attempts(vec![("trips/a", Err(only_failure))])).unwrap_err();
    assert!(matches!(failed, SyncError::NotFound(_)), "{failed}");
}
