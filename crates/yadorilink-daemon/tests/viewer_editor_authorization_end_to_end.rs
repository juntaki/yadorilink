//! Proves the whole sharing-roles authorization pipeline works together,
//! not just each half in isolation.
//!
//! Every prior proof of this mechanism is at the unit level: `daemon_state.
//! rs`'s `local_change_auth_provider_withholds_a_viewers_local_edit_but_
//! allows_an_editor` and `change_auth.rs`'s `accepts_change_auth_rejects_a_
//! viewer_and_accepts_the_same_device_as_an_editor` each inject a hand-built
//! `GroupPolicyState` directly, bypassing the real coordination-plane wire
//! format entirely. This file drives the same two enforcement points through
//! the REAL pipeline instead: a real signed role-carrying grant record
//! (`support::fake_coordination::FakeCoordination::grant_role`, built with
//! this crate's own `change_policy::policy_signing::grant_record` -- the
//! exact shape `coordination-worker`'s `recordGrantWithRole` produces) is
//! served over a real HTTP/WebSocket netmap subscription, fetched and
//! verified by a real daemon (`peer_orchestrator::run`), and enforced by the
//! real `local_change_auth_provider` (local emission) and
//! `NetmapChangeAuthenticator::accepts_change_auth` (remote admission) --
//! full-stack, like `revocation_end_to_end.rs`'s own tests.
//!
//! Three scenarios:
//!   (a) a Viewer-granted device's own local edit is withheld -- never
//!       applied or synced anywhere.
//!   (b) the same setup with an Editor grant instead: the local edit
//!       succeeds and syncs normally -- the control proving this harness
//!       genuinely distinguishes the two roles.
//!   (c) a malicious/buggy client that bypasses its OWN local withholding
//!       check still gets its Viewer-authored Change rejected by the
//!       receiving peer's independent `accepts_change_auth` gate -- defense
//!       in depth, proven with both layers real.
//!
//! A fourth pair covers a DIFFERENT code path guarded by the same gate:
//! `dag_import::ensure_initial_import`/`backfill_missing_history`, which
//! convert a device's pre-existing on-disk content into signed change
//! history the first time a group is linked (or via the mid-life coverage
//! audit) -- not the live filesystem-watcher path scenarios (a)-(c) drive.
//! Both routes end up at the identical `ReplicaCoordinator::
//! local_emission_auth` check, but only a test that seeds content BEFORE
//! the group is ever linked exercises the import/backfill route rather than
//! the watcher route.
//!   (d) a Viewer-granted device's pre-existing content (written to disk
//!       before the group is linked) is never imported into its own local
//!       signed history and never syncs to a peer.
//!   (e) the same setup with an Editor grant instead: the pre-existing
//!       content imports and syncs normally.
//!
//! A sixth pair covers a LIVE role CHANGE while a session is already
//! connected -- the security property that a privilege reduction must
//! invalidate an already-established session's authority promptly, not
//! merely on its next reconnect. `support::fake_coordination::
//! FakeCoordination::downgrade_role` drives the exact chained
//! Revoke-then-Grant record pair `coordination-worker`'s live role-change
//! endpoint produces for a downgrade (a plain Revoke, bumping the group's
//! `auth_epoch`, immediately followed by a Grant at the new, lower role).
//!   (f) an Editor-granted device's session is proven live (a real edit
//!       syncs normally), then downgraded to Viewer WITHOUT tearing down or
//!       reconnecting either daemon's session -- proven by the exact same
//!       `Arc<PeerSyncSession>` on both sides before and after. A NEW local
//!       edit made after the downgrade becomes authoritative is withheld
//!       exactly like scenario (a)'s from-the-start Viewer, proving the
//!       downgrade closed the window promptly through the existing live
//!       netmap-push mechanism, with no daemon-side code change needed.
//!   (g) the same downgrade, but the downgraded device's OWN local
//!       withholding check is bypassed (same technique as scenario (c)) --
//!       the receiving peer's independent `accepts_change_auth` gate still
//!       rejects the change, proving defense in depth holds across a live
//!       downgrade too, not just a from-the-start Viewer grant.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::{register_with_fake, wait_until};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::change_policy::WriterRole;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::peer_orchestrator;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;

static TEST_GUARD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TestDaemon {
    state: Arc<DaemonState>,
}

fn new_test_daemon(device_id: &str) -> TestDaemon {
    let store_dir = tempfile::tempdir().unwrap();
    // Leaked deliberately: the block store must outlive the test; the process
    // tears the temp dir down on exit.
    let store = Arc::new(FsBlockStore::new(Box::leak(Box::new(store_dir)).path()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    TestDaemon { state }
}

fn link(state: &Arc<DaemonState>, root: &std::path::Path, group_id: &str) {
    let local_path = root.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(state.clone()).start(local_path, group_id.to_string()).unwrap();
}

fn spawn_orchestrator(coordination_addr: String, device_id: String, state: Arc<DaemonState>) {
    let config = peer_orchestrator::OrchestratorConfig {
        coordination_addr,
        access_token: "test".to_string(),
        device_id,
    };
    tokio::spawn(async move {
        let _ = peer_orchestrator::run(config, state).await;
    });
}

/// Waits until `state`'s own verified policy chain for `group_id` has
/// reached at least `seq` -- i.e. this device has actually received and
/// verified the real signed grant record(s) `FakeCoordination::grant_role`
/// appended, through its own real netmap subscription, not merely that
/// *some* (possibly still-empty, seq-0) verified state exists.
///
/// Every scenario below waits on this before making its authorization-
/// sensitive move, because `DaemonState::resolve_group_policy` returns
/// `Withhold` (blocking ANY local write, regardless of role) for the whole
/// window between a device being introduced to a group and that group's
/// real policy actually loading. Skipping this wait would make an Editor's
/// legitimate write occasionally flaky (withheld for an unrelated timing
/// reason) and would make a Viewer's withheld write "pass" for the wrong
/// reason on a slow run.
async fn wait_for_group_policy_seq(state: &Arc<DaemonState>, group_id: &str, seq: u64) {
    wait_until(
        || {
            state
                .group_policy_state(group_id)
                .map(|policy| policy.current_seq >= seq)
                .unwrap_or(false)
        },
        Duration::from_secs(20),
    )
    .await;
}

/// Common two-device setup shared by all three scenarios: registers device A
/// and device B with the fake coordination plane, grants device B `b_role`
/// for `group_id` through a real signed record, links both devices into the
/// group, starts both real daemons' `peer_orchestrator`s, and waits until
/// their session has handshaked and both sides have verified the real
/// policy chain (see `wait_for_group_policy_seq`'s own doc comment for why
/// the latter matters).
async fn setup_two_devices(
    fake: &FakeCoordination,
    device_a_id: &str,
    device_b_id: &str,
    group_id: &str,
    b_role: WriterRole,
) -> (TestDaemon, TestDaemon, tempfile::TempDir, tempfile::TempDir) {
    let daemon_a = new_test_daemon(device_a_id);
    let daemon_b = new_test_daemon(device_b_id);
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    register_with_fake(fake, &daemon_a.state, device_a_id, &[group_id]).await;
    register_with_fake(fake, &daemon_b.state, device_b_id, &[group_id]).await;
    // Device B's role grant -- a real signed `ACTION_GRANT_WITH_ROLE`
    // record, matching `coordination-worker`'s own `recordGrantWithRole`
    // shape. Issued before either daemon's orchestrator connects, so each
    // device's very first netmap frame already carries the full chain.
    fake.grant_role(device_b_id, group_id, b_role);

    link(&daemon_a.state, root_a.path(), group_id);
    link(&daemon_b.state, root_b.path(), group_id);

    spawn_orchestrator(fake.addr(), device_a_id.to_string(), daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_b_id.to_string(), daemon_b.state.clone());

    wait_until(
        || {
            daemon_a
                .state
                .peers
                .session(device_b_id)
                .is_some_and(|session| session.peer_handshake_received())
        },
        Duration::from_secs(40),
    )
    .await;
    wait_for_group_policy_seq(&daemon_a.state, group_id, 1).await;
    wait_for_group_policy_seq(&daemon_b.state, group_id, 1).await;

    (daemon_a, daemon_b, root_a, root_b)
}

/// Scenario (a): a Viewer-granted device's own local edit, made through the
/// real filesystem-watch pipeline, must never be applied or synced to a
/// peer -- proving the real `local_change_auth_provider` fix
/// (`daemon_state.rs`) actually engages through this real end-to-end
/// pipeline, not just against a synthetic fixture.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn viewer_granted_devices_local_edit_is_withheld_not_applied_or_synced() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-viewer-withheld";
    let device_b_id = "device-b-viewer-withheld";
    let group_id = "group-viewer-withheld";

    let (_daemon_a, daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Viewer).await;

    // Device B (Viewer-only) makes a real local edit through the real
    // filesystem-watch pipeline.
    std::fs::write(root_b.path().join("viewer-edit.txt"), b"must never sync").unwrap();

    // Generous settle window: long enough that any real sync would have
    // completed several times over -- scenario (b) below observes a
    // legitimate sync land well under this bound in the same process.
    tokio::time::sleep(Duration::from_secs(8)).await;

    // Not synced anywhere: the peer never receives it. On its own this is
    // NOT sufficient to prove local_change_auth_provider specifically did
    // the withholding -- the second, independent enforcement layer
    // (`NetmapChangeAuthenticator::accepts_change_auth` on A's receiving
    // side) would refuse the same Change even if B's own local gate were
    // broken, since B is genuinely a Viewer in the real policy chain either
    // way (see scenario (c), and this file's own RED-verification notes).
    // So this assertion alone cannot distinguish "local emission correctly
    // withheld it" from "local emission signed and sent it, but the peer's
    // independent check caught it" -- the next assertion closes that gap.
    assert!(
        !root_a.path().join("viewer-edit.txt").exists(),
        "a Viewer-granted device's local edit must never be applied or synced to a peer"
    );

    // Not applied to device B's own local state, specifically: local
    // emission calls `local_emission_auth` BEFORE ever touching
    // `file_index_repository` (see `replica_coordinator/local_mutation.rs`'s
    // `upsert_file_emitting_change`), so a withheld edit never reaches B's
    // own file index at all. This is the assertion that actually isolates
    // `local_change_auth_provider`'s own behavior from the second
    // enforcement layer -- it is checked purely on B's own local state,
    // never touching A or the network.
    let indexed_on_b = daemon_b
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(group_id, "viewer-edit.txt")
        .unwrap();
    assert!(
        indexed_on_b.is_none(),
        "a Viewer-granted device's own local file index must never record the withheld edit -- \
         local_change_auth_provider must reject it before file_index_repository::\
         upsert_file_emitting_change ever runs, got {indexed_on_b:?}"
    );
}

/// Scenario (b): the identical setup, but device B is granted Editor
/// instead of Viewer -- its local edit must succeed and sync normally. The
/// control/contrast case proving this harness genuinely distinguishes the
/// two roles rather than accidentally testing something that always fails
/// (or always passes) regardless of role.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn editor_granted_devices_local_edit_succeeds_and_syncs_normally() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-editor-control";
    let device_b_id = "device-b-editor-control";
    let group_id = "group-editor-control";

    let (_daemon_a, _daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Editor).await;

    std::fs::write(root_b.path().join("editor-edit.txt"), b"editor edits sync normally").unwrap();

    wait_until(|| root_a.path().join("editor-edit.txt").exists(), Duration::from_secs(40)).await;
    assert_eq!(
        std::fs::read(root_a.path().join("editor-edit.txt")).unwrap(),
        b"editor edits sync normally",
        "an Editor-granted device's local edit must sync to a peer with unchanged content"
    );
}

/// Scenario (c): defense in depth. Device B is Viewer-only, exactly like
/// scenario (a), but this test simulates a malicious/buggy client that
/// bypasses its OWN local withholding check
/// (`DaemonState::install_unconditional_local_change_auth_provider_for_
/// test`, which reproduces the pre-fix "stamp every local edit
/// unconditionally" bug for this ONE device only) -- so B's edit gets
/// signed with a Viewer-only `ChangeAuth` and sent to A exactly the way a
/// real Editor's edit would be. Everything downstream of that one swapped
/// gate (signing, DAG write, and the real wire delivery to A) is genuine,
/// unmodified production code, so the only thing this proves is whether
/// A's own, completely independent `NetmapChangeAuthenticator::
/// accepts_change_auth`/`author_was_writer_at` gate rejects it on receipt
/// -- the SECOND enforcement layer, holding even when the first is
/// defeated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn viewer_authored_change_that_bypasses_local_withholding_is_rejected_by_the_peer() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-viewer-wire-reject";
    let device_b_id = "device-b-viewer-wire-reject";
    let group_id = "group-viewer-wire-reject";

    let (_daemon_a, daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Viewer).await;

    daemon_b.state.install_unconditional_local_change_auth_provider_for_test();

    std::fs::write(
        root_b.path().join("malicious-edit.txt"),
        b"a viewer must never get this applied",
    )
    .unwrap();

    tokio::time::sleep(Duration::from_secs(8)).await;

    assert!(
        !root_a.path().join("malicious-edit.txt").exists(),
        "a Change authored under a Viewer-only grant must be rejected by the receiving peer's \
         own NetmapChangeAuthenticator::accepts_change_auth, even when the sender's own local \
         withholding check is bypassed"
    );
}

/// Shared body for scenarios (d)/(e): device B has `role` for `group_id`,
/// and its local disk already holds `pre-existing.txt` BEFORE the group is
/// ever linked -- exactly the state `dag_import::ensure_initial_import`
/// exists to convert into signed history on first link, and the state
/// `backfill_missing_history`'s coverage audit exists to catch if that
/// one-shot import is itself withheld waiting on policy to load. `expect_
/// synced` selects which outcome is asserted: `false` for Viewer (never
/// imported, never synced), `true` for Editor (imported and synced
/// normally) -- the control proving this scenario pair genuinely
/// distinguishes the two roles rather than testing something that always
/// passes or always fails regardless of role.
async fn pre_existing_content_initial_import_scenario(role: WriterRole, expect_synced: bool) {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let suffix = if expect_synced { "editor" } else { "viewer" };
    let device_a_id = format!("device-a-preexisting-{suffix}");
    let device_b_id = format!("device-b-preexisting-{suffix}");
    let group_id = format!("group-preexisting-{suffix}");

    let daemon_a = new_test_daemon(&device_a_id);
    let daemon_b = new_test_daemon(&device_b_id);
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();

    // Content already on B's disk BEFORE the group is linked at all -- the
    // scenario `ensure_initial_import` exists for, distinct from scenarios
    // (a)-(c)'s live watcher edits made AFTER linking.
    std::fs::write(root_b.path().join("pre-existing.txt"), b"already on disk before link").unwrap();

    register_with_fake(&fake, &daemon_a.state, &device_a_id, &[&group_id]).await;
    register_with_fake(&fake, &daemon_b.state, &device_b_id, &[&group_id]).await;
    fake.grant_role(&device_b_id, &group_id, role);

    link(&daemon_a.state, root_a.path(), &group_id);
    link(&daemon_b.state, root_b.path(), &group_id);

    spawn_orchestrator(fake.addr(), device_a_id.clone(), daemon_a.state.clone());
    spawn_orchestrator(fake.addr(), device_b_id.clone(), daemon_b.state.clone());

    wait_until(
        || {
            daemon_a
                .state
                .peers
                .session(&device_b_id)
                .is_some_and(|session| session.peer_handshake_received())
        },
        Duration::from_secs(40),
    )
    .await;
    wait_for_group_policy_seq(&daemon_a.state, &group_id, 1).await;
    wait_for_group_policy_seq(&daemon_b.state, &group_id, 1).await;

    if expect_synced {
        wait_until(|| root_a.path().join("pre-existing.txt").exists(), Duration::from_secs(40))
            .await;
        assert_eq!(
            std::fs::read(root_a.path().join("pre-existing.txt")).unwrap(),
            b"already on disk before link",
            "an Editor-granted device's pre-existing content must import and sync to a peer with \
             unchanged content"
        );
        assert_eq!(
            daemon_b.state.replica_coordinator.sqlite().dag_group_heads(&group_id).unwrap().len(),
            1,
            "an Editor-granted device's initial import must commit exactly one head locally"
        );
    } else {
        // Generous settle window: long enough that any real import+sync
        // would have completed several times over -- the Editor variant of
        // this same scenario observes it land well under this bound.
        tokio::time::sleep(Duration::from_secs(8)).await;

        assert!(
            !root_a.path().join("pre-existing.txt").exists(),
            "a Viewer-granted device's pre-existing content must never sync to a peer"
        );
        assert!(
            daemon_b
                .state
                .replica_coordinator
                .sqlite()
                .dag_group_heads(&group_id)
                .unwrap()
                .is_empty(),
            "a Viewer-granted device's pre-existing content must never be committed to its own \
             local signed change history -- ensure_initial_import/backfill_missing_history must \
             withhold it through the same local_emission_auth gate the live local-edit path uses"
        );
    }
}

/// Scenario (d): a Viewer-granted device's pre-existing local content (on
/// disk before the group is ever linked) must never be committed to its own
/// local signed DAG history by the initial-import/coverage-backfill path,
/// and must never sync to a peer -- proving the shared `local_emission_auth`
/// gate that scenario (a) proves for the live watcher path also covers this
/// separate construction path through the real production pipeline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn viewer_granted_devices_pre_existing_content_initial_import_is_withheld() {
    pre_existing_content_initial_import_scenario(WriterRole::Viewer, false).await;
}

/// Scenario (e): the identical setup, but device B is granted Editor
/// instead of Viewer -- its pre-existing content imports and syncs
/// normally. The control/contrast case proving scenario (d) genuinely
/// distinguishes the two roles.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn editor_granted_devices_pre_existing_content_initial_import_succeeds() {
    pre_existing_content_initial_import_scenario(WriterRole::Editor, true).await;
}

/// Waits until `state`'s own verified policy chain for `group_id` reflects a
/// downgrade -- `writers_up_to`/`current_writers` exclude Viewers, so
/// `current_seq` alone (as `wait_for_group_policy_seq` checks) cannot tell
/// "downgraded" apart from "not caught up yet" for a device this daemon
/// itself has no writer-set visibility into from outside; polling the
/// device's own `current_epoch` instead is unambiguous, since only a
/// Revoke (this downgrade's own chained first record) ever bumps it.
async fn wait_for_group_policy_epoch(state: &Arc<DaemonState>, group_id: &str, epoch: u64) {
    wait_until(
        || {
            state
                .group_policy_state(group_id)
                .map(|policy| policy.current_epoch >= epoch)
                .unwrap_or(false)
        },
        Duration::from_secs(20),
    )
    .await;
}

/// Scenario (f): the security property that a live role downgrade must
/// invalidate an already-established, currently-connected session's write
/// privileges promptly, without requiring a reconnect. Device B starts as a
/// genuine Editor with a real, already-connected, already-productive
/// session to device A (proven by a real edit syncing first) -- then gets
/// downgraded to Viewer via `FakeCoordination::downgrade_role`'s chained
/// Revoke-then-Grant, WITHOUT either daemon's `peer_orchestrator` ever being
/// restarted or its session torn down and reconnected (proven directly by
/// `Arc::ptr_eq` on the exact same `PeerSyncSession` object on both sides,
/// before and after). A brand-new local edit made only after the downgrade
/// becomes authoritative (this device's own verified policy epoch has
/// advanced) must be withheld exactly like scenario (a)'s from-the-start
/// Viewer -- proving the existing live netmap-push mechanism
/// (`record_group_policy_states` re-run on every netmap frame,
/// `local_change_auth_provider`'s per-emission re-check against the
/// freshest verified policy) already closes the "stale session keeps
/// operating under old privileges" gap on its own, with no daemon-side
/// production code change required for this to hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn editor_downgraded_to_viewer_mid_session_cannot_author_accepted_changes_without_reconnecting(
) {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-live-downgrade";
    let device_b_id = "device-b-live-downgrade";
    let group_id = "group-live-downgrade";

    let (daemon_a, daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Editor).await;

    // Prove the session is genuinely live and productive as an Editor
    // BEFORE the downgrade -- the control that distinguishes "the downgrade
    // closed a real, working privilege" from "nothing was ever working
    // anyway".
    std::fs::write(root_b.path().join("before-downgrade.txt"), b"editor edit, pre-downgrade")
        .unwrap();
    wait_until(|| root_a.path().join("before-downgrade.txt").exists(), Duration::from_secs(40))
        .await;
    assert_eq!(
        std::fs::read(root_a.path().join("before-downgrade.txt")).unwrap(),
        b"editor edit, pre-downgrade"
    );

    // Snapshot both directions' session objects before the downgrade, to
    // later prove neither daemon reconnected because of it.
    let session_b_to_a_before = daemon_b
        .state
        .peers
        .session(device_a_id)
        .expect("device B must have a live session to device A before the downgrade");
    let session_a_to_b_before = daemon_a
        .state
        .peers
        .session(device_b_id)
        .expect("device A must have a live session to device B before the downgrade");

    // The downgrade itself: chained Revoke (bumps auth_epoch) + Grant at
    // Viewer, pushed over the SAME live netmap subscription both daemons
    // already hold open -- no daemon restart, no new connection.
    fake.downgrade_role(device_b_id, group_id, WriterRole::Viewer);

    // Wait for BOTH daemons' own verified policy state to actually observe
    // the downgrade (not merely for the push to have been sent) -- this is
    // the same real, verified-chain-driven authorization state
    // `local_change_auth_provider` (on B) and `accepts_change_auth` (on A)
    // each independently consult.
    wait_for_group_policy_epoch(&daemon_a.state, group_id, 1).await;
    wait_for_group_policy_epoch(&daemon_b.state, group_id, 1).await;

    // Neither session was torn down and reconnected by the downgrade --
    // this is the literal "already-established session", not a fresh one
    // that merely happens to see the new role on its first connect.
    let session_b_to_a_after = daemon_b
        .state
        .peers
        .session(device_a_id)
        .expect("device B's session to device A must still be live after the downgrade");
    let session_a_to_b_after = daemon_a
        .state
        .peers
        .session(device_b_id)
        .expect("device A's session to device B must still be live after the downgrade");
    assert!(
        Arc::ptr_eq(&session_b_to_a_before, &session_b_to_a_after),
        "the downgrade must not tear down and reconnect device B's session -- this test proves an \
         IN-FLIGHT session is invalidated, not merely a future reconnection"
    );
    assert!(
        Arc::ptr_eq(&session_a_to_b_before, &session_a_to_b_after),
        "the downgrade must not tear down and reconnect device A's session either"
    );

    // The actual security assertion: a NEW local edit, made only after the
    // downgrade became authoritative, over the SAME still-connected session.
    std::fs::write(root_b.path().join("after-downgrade.txt"), b"must never sync post-downgrade")
        .unwrap();

    // Same generous settle window scenario (a) uses.
    tokio::time::sleep(Duration::from_secs(8)).await;

    assert!(
        !root_a.path().join("after-downgrade.txt").exists(),
        "a device downgraded to Viewer mid-session must never sync a NEW edit made after the \
         downgrade became authoritative, without needing to reconnect first"
    );
    let indexed_on_b = daemon_b
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(group_id, "after-downgrade.txt")
        .unwrap();
    assert!(
        indexed_on_b.is_none(),
        "the downgraded device's own local file index must never record the post-downgrade edit -- \
         local_change_auth_provider must reject it before file_index_repository::\
         upsert_file_emitting_change ever runs, got {indexed_on_b:?}"
    );
}

/// Scenario (g): defense in depth for the live-downgrade path, mirroring
/// scenario (c)'s from-the-start-Viewer proof. Device B is downgraded to
/// Viewer exactly like scenario (f), but this test then simulates a
/// malicious/buggy client that bypasses its OWN local withholding check
/// (`DaemonState::install_unconditional_local_change_auth_provider_for_
/// test`) -- so B's post-downgrade edit gets signed and sent to A exactly
/// the way a real Editor's edit would be. The only thing this proves is
/// whether A's own, completely independent `NetmapChangeAuthenticator::
/// accepts_change_auth`/`author_was_writer_at` gate rejects it on receipt --
/// the SECOND enforcement layer, holding even when the first is defeated,
/// even for a device that WAS a legitimate Editor moments earlier in the
/// same live session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn editor_downgraded_to_viewer_mid_session_change_is_rejected_by_the_peer_even_if_local_withholding_is_bypassed(
) {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-live-downgrade-bypass";
    let device_b_id = "device-b-live-downgrade-bypass";
    let group_id = "group-live-downgrade-bypass";

    let (daemon_a, daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Editor).await;

    fake.downgrade_role(device_b_id, group_id, WriterRole::Viewer);
    wait_for_group_policy_epoch(&daemon_a.state, group_id, 1).await;
    wait_for_group_policy_epoch(&daemon_b.state, group_id, 1).await;

    // Bypass B's OWN local withholding check -- everything downstream
    // (signing, DAG write, real wire delivery to A) stays genuine,
    // unmodified production code.
    daemon_b.state.install_unconditional_local_change_auth_provider_for_test();

    std::fs::write(
        root_b.path().join("malicious-post-downgrade.txt"),
        b"a downgraded viewer must never get this applied",
    )
    .unwrap();

    tokio::time::sleep(Duration::from_secs(8)).await;

    assert!(
        !root_a.path().join("malicious-post-downgrade.txt").exists(),
        "a Change authored under a just-downgraded Viewer grant must be rejected by the receiving \
         peer's own NetmapChangeAuthenticator::accepts_change_auth, even when the sender's own \
         local withholding check is bypassed"
    );
}

/// Scenario (h): the realistic attacker a live role downgrade must actually
/// stop -- a STALE-PIN replay, not scenario (g)'s weakest-possible one.
///
/// Device B is a genuine Editor and captures the exact `ChangeAuth` its own
/// real, currently-verified policy state legitimately produces at that
/// moment -- this is genuinely valid the instant it's captured, precisely
/// what B's own real `local_change_auth_provider` would stamp a live edit
/// with right then. Device B is THEN downgraded to Viewer exactly like
/// scenario (f)/(g) -- but instead of scenario (g)'s bypass (which still
/// stamps with the CURRENT, post-downgrade watermark), this device keeps
/// stamping every subsequent local edit with the OLD, pre-downgrade
/// `ChangeAuth` it captured before the downgrade: modeling a still-connected,
/// otherwise-legitimate client that simply has not re-derived its
/// authorization stamp since capturing it -- there is no bug in a client
/// doing this.
///
/// `GroupPolicyState::author_was_writer_at` alone authorizes a Change
/// against exactly the historical policy point its pin names, which WAS
/// genuinely valid the moment it was captured -- so without the receiver's
/// additional live-admission freshness floor (`author_is_writer_now`, wired
/// through `NetmapChangeAuthenticator::accepts_live_change_auth`), this
/// Change is wrongly accepted, and would stay wrongly accepted forever: B
/// could keep replaying this exact stale pin indefinitely, never needing a
/// fresh one, since nothing about replaying it again ever fails on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn editor_downgraded_to_viewer_replaying_a_stale_pre_downgrade_pin_is_rejected_by_the_peer() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-stale-pin-replay";
    let device_b_id = "device-b-stale-pin-replay";
    let group_id = "group-stale-pin-replay";

    let (daemon_a, daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Editor).await;

    // Capture the exact ChangeAuth device B's real, currently-verified
    // Editor policy state legitimately produces right now -- genuinely valid
    // at the instant it's captured.
    let stale_auth = daemon_b
        .state
        .group_policy_state(group_id)
        .expect("device B must have a verified Editor policy state before the downgrade")
        .change_auth();

    fake.downgrade_role(device_b_id, group_id, WriterRole::Viewer);
    wait_for_group_policy_epoch(&daemon_a.state, group_id, 1).await;
    wait_for_group_policy_epoch(&daemon_b.state, group_id, 1).await;

    // Keep stamping every new local edit with the STALE, pre-downgrade
    // pin -- not scenario (g)'s bypass, which still uses the CURRENT
    // (post-downgrade) watermark and so never actually exercises this gap.
    daemon_b.state.install_stale_pin_local_change_auth_provider_for_test(stale_auth);

    std::fs::write(
        root_b.path().join("stale-pin-replay.txt"),
        b"a stale pre-downgrade pin must never get this applied",
    )
    .unwrap();

    tokio::time::sleep(Duration::from_secs(8)).await;

    assert!(
        !root_a.path().join("stale-pin-replay.txt").exists(),
        "a Change replaying a STALE, pre-downgrade ChangeAuth pin must be rejected by the \
         receiving peer's live-admission freshness check, even though the pin was genuinely \
         valid at the moment it was originally captured -- this is the actual proven exploit: \
         author_was_writer_at alone authorizes against the pin's own historical point, never \
         re-checking whether the author is STILL a writer at the receiver's current policy state"
    );
}

/// Proves constraint 1 the other direction: fixing the stale-pin replay gap
/// above must NOT retroactively invalidate a device's LEGITIMATELY-authored
/// history from before it was downgraded. Device B (Editor) authors a real
/// edit that syncs to A normally -- proving it landed as genuine, admitted
/// history, not merely that it was attempted. Device B is THEN downgraded to
/// Viewer. The pre-downgrade edit must remain exactly as synced (never
/// rolled back, quarantined, or removed), and -- the actual mechanism this
/// test exists to exercise -- device A's own retained-history
/// re-validator (`NetmapChangeAuthenticator::validate_retained_group`, the
/// SAME re-authentication `effective_servable_groups`/
/// `validate_linked_history_best_effort` run on every new peer session and
/// netmap update) must still positively authenticate that retained change
/// after the downgrade, proving `author_was_writer_at` -- not the new
/// `author_is_writer_now` freshness floor -- remains the check retained
/// history is judged by.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downgraded_devices_pre_downgrade_history_remains_valid_retained_history() {
    let _test_guard = TEST_GUARD.lock().await;
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    fake.enable_signed_policy();
    let device_a_id = "device-a-retained-history-ok";
    let device_b_id = "device-b-retained-history-ok";
    let group_id = "group-retained-history-ok";

    let (daemon_a, daemon_b, root_a, root_b) =
        setup_two_devices(&fake, device_a_id, device_b_id, group_id, WriterRole::Editor).await;

    // A genuine, legitimately-authored Editor edit, synced before any
    // downgrade -- this is the retained history the fix must never
    // quarantine.
    std::fs::write(root_b.path().join("legitimate-before-downgrade.txt"), b"legitimately authored")
        .unwrap();
    wait_until(
        || root_a.path().join("legitimate-before-downgrade.txt").exists(),
        Duration::from_secs(40),
    )
    .await;
    assert_eq!(
        std::fs::read(root_a.path().join("legitimate-before-downgrade.txt")).unwrap(),
        b"legitimately authored"
    );

    fake.downgrade_role(device_b_id, group_id, WriterRole::Viewer);
    wait_for_group_policy_epoch(&daemon_a.state, group_id, 1).await;
    wait_for_group_policy_epoch(&daemon_b.state, group_id, 1).await;

    // The already-synced content must remain exactly as it was -- the
    // downgrade must not roll back or remove anything already legitimately
    // admitted.
    assert!(
        root_a.path().join("legitimate-before-downgrade.txt").exists(),
        "a downgrade must never remove or roll back content that was legitimately synced BEFORE \
         the downgrade"
    );
    assert_eq!(
        std::fs::read(root_a.path().join("legitimate-before-downgrade.txt")).unwrap(),
        b"legitimately authored"
    );

    // The actual mechanism proof: device A's own retained-history
    // re-validator must still positively authenticate B's pre-downgrade
    // Change, even now that B is a Viewer -- proving the live-admission
    // freshness floor this fix adds is correctly confined to
    // `accepts_live_change_auth` and never reaches `validate_retained_group`.
    let report =
        yadorilink_daemon::change_auth::NetmapChangeAuthenticator::new(daemon_a.state.clone())
            .validate_retained_group(group_id)
            .expect(
                "retained-history re-validation must still positively authenticate a \
                 since-downgraded device's legitimately-authored past history -- if this fails, \
                 the live-admission freshness fix leaked into retained-history re-validation and \
                 broke it",
            );
    assert!(
        report.verified_changes >= 1,
        "retained-history re-validation must actually walk and verify at least the pre-downgrade \
         change, not vacuously succeed over an empty frontier"
    );

    // Keep both daemons' roots/orchestrators alive for the whole test.
    let _ = (&daemon_a, &daemon_b, &root_b);
}
