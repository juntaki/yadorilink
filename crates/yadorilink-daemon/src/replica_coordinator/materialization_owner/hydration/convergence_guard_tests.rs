//! `ConvergenceHydration`'s revert-on-drop, tested against a real
//! `ReplicaCoordinator`.
//!
//! A child module of the owner's `hydration` module, because the guard's
//! fields are private to it: the tests arm a guard directly, without
//! running the entry CAS, to simulate an attempt already in flight.

use std::sync::Arc;

use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::MaterializationState;

use crate::replica_coordinator::ReplicaCoordinator;

const GROUP: &str = "group-1";

/// `ConvergenceHydration`'s revert-on-drop must not clobber a
/// concurrent hydration attempt for the SAME path that already
/// completed successfully. Even with `hydrate_file_with_timeout` now
/// serializing on `path_lock` (see the test above), a losing internal
/// race within one lock-holding attempt's own retry/backoff logic is
/// still worth guarding directly at this layer too: if this guard's
/// own attempt fails AFTER a different, concurrent
/// attempt already committed a genuine `Hydrated`, an unconditional
/// revert would silently downgrade that successful result back to
/// `Placeholder` even though the file really is on disk -- a real
/// regression in this guard's first version, which used a blind
/// `set_materialization_state`
/// instead of a conditional transition.
#[tokio::test]
async fn hydrating_state_guard_does_not_clobber_a_concurrently_completed_hydration() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let sync_root = root_dir.path().canonicalize().unwrap();
    state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(&sync_root, GROUP, state.as_ref())
        .unwrap();

    state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "doc.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "doc.txt",
            MaterializationState::Hydrating,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // This attempt's own guard, not yet committed -- as if this
    // attempt is still in flight (e.g. about to fail).
    let guard = super::ConvergenceHydration {
        coordinator: state.as_ref(),
        group_id: GROUP,
        path: "doc.txt",
        authoring_change_hash: None,
        // The version this simulated attempt is about: the one the
        // row names right now, since these fixtures seed the row and
        // then move only its materialization state.
        version: state
            .file_index_repository()
            .canonical_current_row(GROUP, "doc.txt")
            .unwrap()
            .unwrap()
            .version_hash(),
        revert_to: MaterializationState::Placeholder,
        committed: false,
    };

    // A DIFFERENT, concurrent attempt for the same path finishes
    // first and genuinely completes.
    state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "doc.txt",
            MaterializationState::Hydrated,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // This attempt's own guard now drops (uncommitted, simulating its
    // own late failure) -- it must NOT downgrade the row the
    // concurrent attempt already finished.
    drop(guard);

    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrated),
        "a losing guard's revert-on-drop must not clobber a concurrently-completed \
         hydration's Hydrated state"
    );
}

/// A state-only CAS (the previous fix) is not enough on its own: it
/// cannot distinguish "this row is still the SAME version this
/// attempt started hydrating, just still `Hydrating`" from "a NEWER
/// version of this same path became `current` mid-hydration (a
/// peer's concurrent update superseding the row) and its own,
/// unrelated hydration attempt happens to also be `Hydrating`". Only
/// binding the CAS to the authoring identity captured before this
/// attempt started closes that gap -- the deeper counter-scenario to
/// the state-only guard above.
#[tokio::test]
async fn hydrating_state_guard_does_not_clobber_a_superseding_newer_version() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let sync_root = root_dir.path().canonicalize().unwrap();
    state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(&sync_root, GROUP, state.as_ref())
        .unwrap();

    state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "doc.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let old_hash = yadorilink_replica_domain::ids::ChangeHash([1u8; 32]);
    state.file_index_repository().set_authoring_change_hash(GROUP, "doc.txt", &old_hash).unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "doc.txt",
            MaterializationState::Hydrating,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // This attempt's own guard, capturing the OLD version's authoring
    // identity, as `hydrate_file_with_timeout` does before it marks
    // the row `Hydrating`.
    let guard = super::ConvergenceHydration {
        coordinator: state.as_ref(),
        group_id: GROUP,
        path: "doc.txt",
        authoring_change_hash: Some(old_hash),
        // The version this simulated attempt is about: the one the
        // row names right now, since these fixtures seed the row and
        // then move only its materialization state.
        version: state
            .file_index_repository()
            .canonical_current_row(GROUP, "doc.txt")
            .unwrap()
            .unwrap()
            .version_hash(),
        revert_to: MaterializationState::Placeholder,
        committed: false,
    };

    // A peer's concurrent update supersedes the row with a genuinely
    // NEWER version, which independently starts its OWN hydration --
    // landing back at `Hydrating`, but for a different identity.
    let new_hash = yadorilink_replica_domain::ids::ChangeHash([2u8; 32]);
    state.file_index_repository().set_authoring_change_hash(GROUP, "doc.txt", &new_hash).unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "doc.txt",
            MaterializationState::Hydrating,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // The OLD attempt's guard now drops (uncommitted) -- state alone
    // matches (`Hydrating`), but the authoring identity does not, so
    // this must be a no-op.
    drop(guard);

    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrating),
        "an old attempt's guard must not touch a newer version's own in-flight hydration \
         just because the state value happens to match"
    );
    assert_eq!(
        state.file_index_repository().get_authoring_change_hash(GROUP, "doc.txt").unwrap(),
        Some(new_hash),
        "the newer version's identity must be untouched"
    );
}

/// The version half of the same binding, which the test above does not
/// reach.
///
/// That one moves only `authoring_change_hash`, leaving every column a
/// version is derived from untouched -- so the row's version never
/// changes and an authoring-only guard would pass it. The guard's own
/// doc comment claims more than that: a supersession can keep the
/// authoring hash while moving the columns the version comes from, and
/// reverting on the hash alone would take a row that has moved on back
/// to `Placeholder`.
///
/// So this moves the version and nothing else. Same author, same
/// `Hydrating` state, different content: only the version binding can
/// tell this row apart from the one the guard captured.
#[tokio::test]
async fn hydrating_state_guard_does_not_clobber_a_same_author_newer_version() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let sync_root = root_dir.path().canonicalize().unwrap();
    state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(&sync_root, GROUP, state.as_ref())
        .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "doc.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    let author = yadorilink_replica_domain::ids::ChangeHash([1u8; 32]);
    state.file_index_repository().set_authoring_change_hash(GROUP, "doc.txt", &author).unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(GROUP, "doc.txt", MaterializationState::Hydrating, &permit)
        .unwrap();

    let captured_version = state
        .file_index_repository()
        .canonical_current_row(GROUP, "doc.txt")
        .unwrap()
        .unwrap()
        .version_hash();
    let guard = super::ConvergenceHydration {
        coordinator: state.as_ref(),
        group_id: GROUP,
        path: "doc.txt",
        authoring_change_hash: Some(author),
        version: captured_version,
        revert_to: MaterializationState::Placeholder,
        committed: false,
    };

    // The supersession: a column the version is derived from moves,
    // and the authoring hash deliberately does not.
    state.file_index_repository().set_unix_mode(GROUP, "doc.txt", Some(0o755), &permit).unwrap();
    let superseding_version = state
        .file_index_repository()
        .canonical_current_row(GROUP, "doc.txt")
        .unwrap()
        .unwrap()
        .version_hash();
    assert_ne!(
        superseding_version, captured_version,
        "fixture check: the supersession must really move the version, or this test proves \
         nothing beyond the authoring-only case above"
    );
    assert_eq!(
        state.file_index_repository().get_authoring_change_hash(GROUP, "doc.txt").unwrap(),
        Some(author),
        "fixture check: and it must leave the authoring identity alone, or the authoring \
         binding would be what catches it"
    );

    drop(guard);

    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrating),
        "an old attempt's guard must not revert a row whose version has moved on, even when \
         the authoring identity it captured still matches"
    );
}
