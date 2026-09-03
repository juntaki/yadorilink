//! Real-hardware acceptance coverage: rename/delete correctness at a modest
//! real scale (hundreds of files), through the full daemon stack (real
//! directly-paired peer sessions, the real OS filesystem watcher via
//! `LinkRuntimeController`).
//!
//! Adapted from a Lane C (macOS platform-acceptance) finding during the C4
//! stall investigation: an equivalent test using `support`'s coordination-
//! server-backed topology (`start_coordination_server`/`register_and_login`/
//! `DeviceKeyPair`) reproduced a real, repeatable bug on real macOS hardware
//! -- all 125 renames converged every time, but a large, varying fraction of
//! 125 plain deletes never converged even after 240s (44/125 undelivered one
//! run, 70/125 another -- two independent fresh runs, not the same run
//! measured twice). This worktree's checkout predates that coordination-
//! plane API (`DeviceKeyPair` does not exist here), so this version uses the
//! same direct-pairing topology `large_folder_scale_sanity.rs` already
//! establishes as working in this tree, to check whether the same
//! delete-convergence gap reproduces here too, on Linux, at this same
//! smaller/faster-to-iterate scale.
//!
//! `load_many_small_files.rs` already covers bulk *create* plus one
//! incremental *create* at a similar file count, but never renames or
//! deletes any of the bulk-created files -- this closes that gap.
//!
//! Not run in CI, same rationale as `load_many_small_files.rs`'s identically
//! tagged test. Run with `cargo test -- --ignored`.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use support::{daemon_status_summary, ensure_device_signing_key, real_entry_names};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::FsBlockStore;

const FILE_COUNT: usize = 1800;
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);
/// Generous, load-tolerant bound -- see the Lane C macOS run's own doc
/// comment history: 90s proved too tight with no sign of an actual stall
/// (just steady incremental progress) before a real regression shows up as
/// no progress at all, not a borderline timing race.
const RENAME_DELETE_TIMEOUT: Duration = Duration::from_secs(240);

#[ignore = "real-scale acceptance test -- run explicitly (cargo test -- --ignored) or via scripts/heat-run.sh, not in CI"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_rename_and_delete_converge_at_modest_scale() {
    let _ = tracing_subscriber::fmt::try_init();

    let group_id = "rename-delete-modest-scale-group".to_string();

    // File-backed (not open_in_memory()), matching large_folder_scale_
    // sanity.rs's own storm harness -- an in-memory SQLite database cannot
    // use WAL mode at all (the pragma is a no-op there), so a long-held
    // read connection can genuinely block a writer under SQLite's default
    // rollback-journal locking in a way that structurally cannot happen
    // against a real, file-backed WAL-mode database. A first attempt at
    // this test with open_in_memory() hit exactly that ("database table
    // is locked: changes") -- a real, but likely DIFFERENT, bug specific
    // to in-memory-mode testing, not the storm's own silent-stall shape.
    let db_dir_a = tempfile::tempdir().unwrap();
    let store_dir_a = tempfile::tempdir().unwrap();
    let store_a = Arc::new(FsBlockStore::new(store_dir_a.path()).unwrap());
    let sync_state_a = Arc::new(ReplicaCoordinator::open(&db_dir_a.path().join("index.db")).unwrap());
    let state_a = DaemonState::new("device-a".to_string(), sync_state_a, store_a);
    ensure_device_signing_key(&state_a);
    let root_a = tempfile::tempdir().unwrap();

    let db_dir_b = tempfile::tempdir().unwrap();
    let store_dir_b = tempfile::tempdir().unwrap();
    let store_b = Arc::new(FsBlockStore::new(store_dir_b.path()).unwrap());
    let sync_state_b = Arc::new(ReplicaCoordinator::open(&db_dir_b.path().join("index.db")).unwrap());
    let state_b = DaemonState::new("device-b".to_string(), sync_state_b, store_b);
    ensure_device_signing_key(&state_b);
    let root_b = tempfile::tempdir().unwrap();

    // Populate device A's folder with FILE_COUNT files before B ever
    // connects, same "initial full sync" path load_many_small_files.rs
    // exercises.
    for i in 0..FILE_COUNT {
        std::fs::write(
            root_a.path().join(format!("file-{i:04}.txt")),
            format!("content of file {i}"),
        )
        .unwrap();
    }

    let local_path_a = root_a.path().to_string_lossy().to_string();
    state_a.replica_coordinator.link_repository().add_link(&local_path_a, &group_id).unwrap();
    LinkRuntimeController::new(state_a.clone()).start(local_path_a, group_id.clone()).unwrap();
    let local_path_b = root_b.path().to_string_lossy().to_string();
    state_b.replica_coordinator.link_repository().add_link(&local_path_b, &group_id).unwrap();
    LinkRuntimeController::new(state_b.clone())
        .start(local_path_b.clone(), group_id.clone())
        .unwrap();

    support::connect_two_daemons(
        &state_a,
        "device-a",
        &state_b,
        "device-b",
        std::slice::from_ref(&group_id),
    )
    .await;

    let started = Instant::now();
    support::wait_until_with_context(
        || real_entry_names(root_b.path()).len() >= FILE_COUNT,
        CONVERGENCE_TIMEOUT,
        || {
            format!(
                "expected >= {FILE_COUNT} files in root_b={:?}, found {}; device_a: {}; device_b: {}",
                root_b.path(),
                real_entry_names(root_b.path()).len(),
                daemon_status_summary(&state_a),
                daemon_status_summary(&state_b),
            )
        },
    )
    .await;
    tracing::info!(elapsed = ?started.elapsed(), FILE_COUNT, "initial bulk sync completed");
    assert_eq!(real_entry_names(root_b.path()).len(), FILE_COUNT);

    // Real-OS-watcher rename/delete, on device A, over the real disk this
    // process is actually running on (inotify on Linux) -- not a
    // simulated/madsim event feed.
    //
    // First half: renamed into a `renamed-` prefix.
    // Second half: deleted outright.
    // C4_DIAG (temporary, remove after investigation): zero the writer_gate
    // counters right before the rename/delete burst, matching large_folder_
    // scale_sanity.rs's storm measurement -- this test converges (or stalls)
    // ~3x faster (287s vs ~900s) while exhibiting the identical "both devices
    // stay connected, no progress" signature, so it doubles as a fast
    // reproduction case for the same investigation.
    yadorilink_sqlite_runtime::c4_diag::reset();
    yadorilink_peer_session::c4_diag::reset();
    let rename_started = Instant::now();
    for i in 0..(FILE_COUNT / 2) {
        std::fs::rename(
            root_a.path().join(format!("file-{i:04}.txt")),
            root_a.path().join(format!("renamed-{i:04}.txt")),
        )
        .unwrap();
    }
    for i in (FILE_COUNT / 2)..FILE_COUNT {
        std::fs::remove_file(root_a.path().join(format!("file-{i:04}.txt"))).unwrap();
    }

    let expected_final_count = FILE_COUNT / 2;
    // C4_DIAG (temporary, remove after investigation): periodic progress +
    // writer_gate/call-site snapshot, ported from large_folder_scale_
    // sanity.rs's storm-wait loop -- see that file for the full rationale.
    {
        let deadline = tokio::time::Instant::now() + RENAME_DELETE_TIMEOUT;
        let mut last_progress_log = tokio::time::Instant::now();
        loop {
            let names = real_entry_names(root_b.path());
            let converged = names.len() == expected_final_count
                && (0..(FILE_COUNT / 2)).all(|i| names.contains(&format!("renamed-{i:04}.txt")));
            if converged {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                let (gate_acquisitions, gate_wait) = yadorilink_sqlite_runtime::c4_diag::stats();
                let call_sites = yadorilink_sqlite_runtime::c4_diag::call_site_stats();
                let top_call_sites: String = call_sites
                    .iter()
                    .take(15)
                    .map(|(loc, n)| format!("{n}x {loc}"))
                    .collect::<Vec<_>>()
                    .join(" | ");
                panic!(
                    "renamed/deleted state never converged in root_b={:?}: {:?}; \
                     writer_gate_acquisitions={gate_acquisitions} writer_gate_wait_ms={} \
                     rename_delete_elapsed_ms={}; device_a: {}; device_b: {}\n\
                     top write() call sites: {top_call_sites}",
                    root_b.path(),
                    names,
                    gate_wait.as_millis(),
                    rename_started.elapsed().as_millis(),
                    daemon_status_summary(&state_a),
                    daemon_status_summary(&state_b),
                );
            }
            if last_progress_log.elapsed() >= Duration::from_secs(30) {
                let (gate_acquisitions, gate_wait) = yadorilink_sqlite_runtime::c4_diag::stats();
                let renamed_present = names.iter().filter(|n| n.starts_with("renamed-")).count();
                tracing::info!(
                    renamed_present,
                    remaining_entries = names.len(),
                    total = expected_final_count,
                    writer_gate_acquisitions = gate_acquisitions,
                    writer_gate_wait_ms = gate_wait.as_millis() as u64,
                    rename_delete_elapsed_ms = rename_started.elapsed().as_millis() as u64,
                    "C4_STORM_PROGRESS"
                );
                let call_sites = yadorilink_sqlite_runtime::c4_diag::call_site_stats();
                let top_call_sites: String = call_sites
                    .iter()
                    .take(10)
                    .map(|(loc, n)| format!("{n}x {loc}"))
                    .collect::<Vec<_>>()
                    .join(" | ");
                tracing::info!(top_call_sites, "C4_STORM_CALL_SITES");

                // C4_DIAG (temporary, remove after investigation): a
                // one-shot diagnostic pass distinguishing "the DAG itself
                // hasn't caught up" from "the DAG has caught up but
                // filesystem materialization is the residual bottleneck"
                // from "the same missing changes are being re-requested
                // redundantly while an earlier request is still in
                // flight". See this repo's own C4 storm-liveness
                // investigation notes for the decision table this feeds.
                let a_heads =
                    state_a.replica_coordinator.sqlite().dag_group_heads(&group_id).unwrap_or_default();
                let b_heads =
                    state_b.replica_coordinator.sqlite().dag_group_heads(&group_id).unwrap_or_default();
                let a_heads_missing_on_b = state_b
                    .replica_coordinator
                    .sqlite()
                    .dag_missing_ancestor_frontier(a_heads.iter().copied())
                    .map(|f| f.len())
                    .unwrap_or(usize::MAX);
                let b_heads_missing_on_a = state_a
                    .replica_coordinator
                    .sqlite()
                    .dag_missing_ancestor_frontier(b_heads.iter().copied())
                    .map(|f| f.len())
                    .unwrap_or(usize::MAX);
                let b_unapplied_changes = state_b
                    .replica_coordinator
                    .change_history_repository()
                    .dag_list_unapplied_changes(&group_id)
                    .map(|c| c.len())
                    .unwrap_or(usize::MAX);
                let b_orphan_count = state_b
                    .replica_coordinator
                    .change_history_repository()
                    .dag_group_diagnostics(&group_id)
                    .map(|d| d.orphan_total)
                    .unwrap_or(u64::MAX);
                tracing::info!(
                    a_group_heads = a_heads.len(),
                    b_group_heads = b_heads.len(),
                    a_heads_missing_on_b,
                    b_heads_missing_on_a,
                    b_unapplied_changes,
                    b_orphan_count,
                    "C4_STORM_DAG"
                );

                let protocol = yadorilink_peer_session::c4_diag::stats();
                tracing::info!(
                    heads_announce_received = protocol.heads_announce_received,
                    change_requests_sent = protocol.change_requests_sent,
                    request_want_len_count = protocol.want_len.count,
                    request_want_len_mean = protocol.want_len.mean,
                    request_want_len_p50 = protocol.want_len.p50,
                    request_want_len_p95 = protocol.want_len.p95,
                    request_want_len_max = protocol.want_len.max,
                    change_batches_received = protocol.change_batches_received,
                    changes_received_total = protocol.changes_received_total,
                    changes_new = protocol.changes_new,
                    changes_already_known = protocol.changes_already_known,
                    changes_orphaned = protocol.changes_orphaned,
                    promoted_orphans = protocol.promoted_orphans,
                    "C4_STORM_PROTOCOL"
                );

                last_progress_log = tokio::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    tracing::info!(
        elapsed = ?rename_started.elapsed(),
        FILE_COUNT,
        "bulk rename+delete converged"
    );

    let final_names = real_entry_names(root_b.path());
    assert_eq!(final_names.len(), expected_final_count, "final={final_names:?}");
    for i in 0..(FILE_COUNT / 2) {
        let renamed_path = root_b.path().join(format!("renamed-{i:04}.txt"));
        assert!(renamed_path.exists(), "missing {renamed_path:?}");
        assert_eq!(
            std::fs::read_to_string(&renamed_path).unwrap(),
            format!("content of file {i}"),
            "renamed file lost its content: {renamed_path:?}"
        );
        assert!(!root_b.path().join(format!("file-{i:04}.txt")).exists());
    }
    for i in (FILE_COUNT / 2)..FILE_COUNT {
        assert!(!root_b.path().join(format!("file-{i:04}.txt")).exists());
        assert!(!root_b.path().join(format!("renamed-{i:04}.txt")).exists());
    }

    // Converged and stayed converged -- no runaway re-sync loop from the
    // rename/delete burst.
    assert_eq!(real_entry_names(root_b.path()).len(), expected_final_count);
}
