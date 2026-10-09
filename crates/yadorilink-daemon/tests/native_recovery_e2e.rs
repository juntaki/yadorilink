//! Native recovery in real daemons: a device whose peers can no longer replay
//! the deltas it needs is brought up to date by a sealed bundle of the peer's
//! state, which it verifies and installs, and whose files it then materializes.
//! A device that holds no native state installs the bundle as a first join; a
//! device that holds state replaces it through the rebootstrap machine, which
//! the daemon drives from its journal.

mod native_e2e_support;
mod support;

use native_e2e_support::*;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_sqlite::native_checkpoint_frontier::{
    checkpoint_frontier, most_recently_adopted_checkpoint,
};
use yadorilink_sync_sqlite::native_store;

const GROUP: &str = "native-recovery-group";

fn setup() {
    support::ensure_isolated_config_dir();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

fn frontier_len(node: &TopologyNode) -> usize {
    read(node, |conn| {
        native_store::load_frontier(conn, &FolderGroupId(GROUP.to_owned())).map(|f| f.len())
    })
}

/// A fresh device is linked after the history it needs was collected: it
/// cannot replay it, so it receives the sealed state, and its folder ends up
/// holding the same files.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_fresh_device_recovers_from_a_sealed_state_and_materializes_its_files() {
    setup();
    let a = device("rec-a", GROUP);
    let b = device("rec-b", GROUP);
    pair(&a, &b, GROUP).await;

    // Each file converges before the next is written, so each is signed in a
    // delta of its own: a delta that signed several files is collectable only
    // once none of its heads is live.
    write(&a, "doc.txt", b"first");
    converge_to(&[&a, &b], &[("doc.txt", b"first")], "doc").await;
    write(&a, "dir/nested.txt", b"nested");
    converge_to(&[&a, &b], &[("doc.txt", b"first"), ("dir/nested.txt", b"nested")], "nested").await;
    write(&a, "gone.txt", b"to be removed");
    converge_to(
        &[&a, &b],
        &[("doc.txt", b"first"), ("dir/nested.txt", b"nested"), ("gone.txt", b"to be removed")],
        "initial",
    )
    .await;
    write(&a, "doc.txt", b"second");
    remove(&a, "gone.txt");
    converge_to(&[&a, &b], &[("doc.txt", b"second"), ("dir/nested.txt", b"nested")], "edits").await;
    converge_state(&[&a, &b], GROUP, "one native state").await;

    // The superseded deltas are collected on every holder.
    assert!(collect_replication_log(&a, GROUP) > 0, "something was collectable");
    collect_replication_log(&b, GROUP);

    let c = device("rec-c", GROUP);
    assert_eq!(frontier_len(&c), 0, "the fresh device holds no native state");
    pair(&c, &a, GROUP).await;

    converge_to(&[&a, &b, &c], &[("doc.txt", b"second"), ("dir/nested.txt", b"nested")], "fresh")
        .await;
    converge_state(&[&a, &b, &c], GROUP, "the fresh device holds the same state").await;
    assert!(frontier_len(&c) > 0, "the recovered state was persisted");

    // The joiner trusts the checkpoint it joined from and the sealer adopted the
    // one it sealed; each holds the frontier that checkpoint covers.
    for (node, who) in [(&c, "the joiner"), (&a, "the sealer")] {
        let (trusted, covered) = read(node, |conn| {
            let group = FolderGroupId(GROUP.to_owned());
            let trusted = most_recently_adopted_checkpoint(conn, &group)?;
            let covered = match &trusted {
                Some(t) => checkpoint_frontier(conn, &group, &t.checkpoint_id)?.len(),
                None => 0,
            };
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>((trusted, covered))
        });
        assert!(trusted.is_some(), "{who} holds a trusted checkpoint");
        assert!(covered > 0, "{who} persisted the frontier its checkpoint covers");
    }
}

/// Installing a sealed state drops the deltas and hold placements the device
/// held before it, so what follows the checkpoint must arrive again through
/// ordinary admission. The peer holding that newer tail is cut off right after
/// the install, before the tail is delivered, and reconnects: the device
/// converges to the peer's files and state, authoring nothing of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_fresh_device_converges_after_the_tail_source_reconnects() {
    setup();
    let a = device("tail-a", GROUP);
    let b = device("tail-b", GROUP);
    pair(&a, &b, GROUP).await;
    write(&a, "doc.txt", b"first");
    converge_to(&[&a, &b], &[("doc.txt", b"first")], "doc").await;
    write(&a, "gone.txt", b"to be removed");
    converge_to(&[&a, &b], &[("doc.txt", b"first"), ("gone.txt", b"to be removed")], "gone").await;
    write(&a, "doc.txt", b"second");
    remove(&a, "gone.txt");
    converge_to(&[&a, &b], &[("doc.txt", b"second")], "edits").await;
    converge_state(&[&a, &b], GROUP, "one native state").await;
    assert!(collect_replication_log(&a, GROUP) > 0, "something was collectable");
    collect_replication_log(&b, GROUP);

    // The fresh device joins through the sealed state, then loses the peer.
    let c = device("tail-c", GROUP);
    pair(&c, &a, GROUP).await;
    converge_to(&[&a, &b, &c], &[("doc.txt", b"second")], "joined").await;
    converge_state(&[&a, &b, &c], GROUP, "installed the sealed state").await;
    assert!(frontier_len(&c) > 0, "the recovered state was persisted");
    partition(&a, &c).await;

    // The tail, written after the checkpoint, exists only on its author:
    // severing a device drops its whole peer stack, so no one else holds it.
    write(&a, "tail.txt", b"tail");
    write(&a, "doc.txt", b"third");
    captured(&a, GROUP).await;
    assert_eq!(tree(&c).get("doc.txt").map(Vec::as_slice), Some(&b"second"[..]));
    assert!(!tree(&c).contains_key("tail.txt"), "the tail has not been delivered yet");

    pair(&c, &a, GROUP).await;
    converge_to(&[&a, &c], &[("doc.txt", b"third"), ("tail.txt", b"tail")], "caught up").await;
    converge_state(&[&a, &c], GROUP, "one native state").await;
    assert!(conflict_copies(&tree(&c)).is_empty(), "nothing was authored twice");
}

/// An existing device replaces its state through a rebootstrap only when its peers can no
/// longer replay what it lacks. While nothing says so (no peer has truncated the history, none
/// is even connected) a sealed state is not taken: the refusal leaves its state and files as they
/// were.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_existing_device_takes_no_sealed_state_while_its_peers_can_still_replay() {
    use yadorilink_daemon::native_recovery::{DaemonRecovery, RecoveryPort};
    setup();
    let a = device("recj-a", GROUP);
    let b = device("recj-b", GROUP);
    pair(&a, &b, GROUP).await;
    write(&a, "kept.txt", b"kept");
    converge_to(&[&a, &b], &[("kept.txt", b"kept")], "initial").await;

    partition(&a, &b).await;
    for content in [&b"one"[..], b"two", b"three"] {
        write(&a, "doc.txt", content);
        captured(&a, GROUP).await;
    }
    assert!(collect_replication_log(&a, GROUP) > 0, "superseded deltas were collected");

    write(&b, "local.txt", b"local");
    captured(&b, GROUP).await;
    let before = native_state(&b, GROUP);
    let group = FolderGroupId(GROUP.to_owned());
    let bundle = DaemonRecovery::new(shared(&a))
        .serve(&group)
        .await
        .expect("the up-to-date device can seal its state");
    let apply_bundle = bundle.clone();
    let b_state = shared(&b).clone();
    let error = tokio::task::spawn_blocking(move || {
        DaemonRecovery::new(&b_state).apply(&group, &apply_bundle)
    })
    .await
    .unwrap()
    .expect_err("no peer has truncated the history, so no rebootstrap starts");
    // Where rebootstrap is refused outright the gate answers before the peers are weighed.
    let expected =
        if rebootstrap_is_refused_here() { "DurabilityUnsupported" } else { "did not start" };
    assert!(error.contains(expected), "{error}");
    assert_eq!(native_state(&b, GROUP), before, "the refused bundle changed nothing");
    assert!(!tree(&b).contains_key("doc.txt"));
    assert!(tree(&b).contains_key("local.txt"));
}

/// An existing device whose peer collected the history it lacks asks for the
/// peer's sealed state on its own and ends up with the peer's files.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_existing_device_asks_for_a_sealed_state_when_its_peer_cannot_replay() {
    setup();
    let a = device("recq-a", GROUP);
    let b = device("recq-b", GROUP);
    pair(&a, &b, GROUP).await;
    write(&a, "kept.txt", b"kept");
    converge_to(&[&a, &b], &[("kept.txt", b"kept")], "initial").await;

    partition(&a, &b).await;
    for content in [&b"one"[..], b"two", b"three"] {
        write(&a, "doc.txt", content);
        captured(&a, GROUP).await;
    }
    assert!(collect_replication_log(&a, GROUP) > 0, "superseded deltas were collected");
    if rebootstrap_refused_and_state_intact(&a, &b).await {
        return;
    }

    pair(&a, &b, GROUP).await;
    converge_to(&[&a, &b], &[("kept.txt", b"kept"), ("doc.txt", b"three")], "recovered").await;
    converge_state(&[&a, &b], GROUP, "one native state").await;
}

/// A device that recovered from a sealed state holds the sender's whole
/// frontier but the signed deltas only of what is live, so it cannot replay
/// the rest of the history to a device that lags behind. That device already
/// holds state of the group, yet the author who could have supplied the history
/// is gone: it takes the recovered peer's sealed state, which descends from its
/// own, and ends with the same files and the same state.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lagging_device_catches_up_from_a_recovered_peer_once_the_author_is_gone() {
    setup();
    let a = device("cu-a", GROUP);
    let c = device("cu-c", GROUP);
    pair(&a, &c, GROUP).await;
    write(&a, "x.txt", b"first");
    converge_to(&[&a, &c], &[("x.txt", b"first")], "initial").await;

    // The author removes the file while `c` is away, and collects what no live
    // head rests on.
    partition(&a, &c).await;
    remove(&a, "x.txt");
    captured(&a, GROUP).await;
    assert!(collect_replication_log(&a, GROUP) > 0, "the superseded deltas were collected");

    // `b` is a new device that can only recover: it holds no body of the history.
    let b = device("cu-b", GROUP);
    pair(&b, &a, GROUP).await;
    converge_state(&[&a, &b], GROUP, "the new device recovered the author's state").await;
    assert!(frontier_len(&b) > 0, "the recovered state was persisted");
    assert!(!tree(&b).contains_key("x.txt"));

    // The author goes away; `c` reconciles with the recovered peer alone.
    partition(&a, &b).await;
    assert!(tree(&c).contains_key("x.txt"), "`c` still shows the file it last saw");
    if rebootstrap_refused_and_state_intact(&b, &c).await {
        return;
    }
    pair(&c, &b, GROUP).await;
    converge_to(&[&b, &c], &[], "the lagging device caught up").await;
    converge_state(&[&b, &c], GROUP, "one native state").await;
}

/// A peer reports more of this device's own author than it has signed (another
/// copy wrote under the same identity). The next local write must not sign as
/// that author: it rotates the incarnation first and then reaches the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_whose_own_author_is_reported_ahead_rotates_before_it_signs() {
    use yadorilink_sync_sqlite::author_incarnation;
    setup();
    let a = device("ahead-a", GROUP);
    let b = device("ahead-b", GROUP);
    pair(&a, &b, GROUP).await;
    write(&a, "before.txt", b"before");
    converge_to(&[&a, &b], &[("before.txt", b"before")], "initial").await;

    let before = read(&a, author_incarnation::current_author);
    let local = read(&a, |conn| {
        native_store::frontier_entry_get(conn, &FolderGroupId(GROUP.to_owned()), &before)
            .map(|entry| entry.expect("the device authored").seq)
    });
    a.state
        .replica_coordinator
        .database()
        .write(|conn| {
            author_incarnation::note_own_author_ahead(
                conn,
                GROUP,
                &author_incarnation::OwnAuthorAhead {
                    author: before.clone(),
                    local,
                    reported: yadorilink_replica_domain::ids::AuthorSeq(local.0 + 5),
                },
            )
        })
        .unwrap();

    write(&a, "after.txt", b"after");
    converge_to(&[&a, &b], &[("before.txt", b"before"), ("after.txt", b"after")], "after").await;

    let after = read(&a, author_incarnation::current_author);
    assert_ne!(after, before, "the incarnation was rotated before signing");
    assert!(
        read(&a, |conn| author_incarnation::own_author_ahead(conn, GROUP)).is_none(),
        "the report is resolved by the rotation"
    );
}

fn count_rows(node: &TopologyNode, table: &str) -> i64 {
    read(node, |conn| {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0))
            .map_err(Into::into)
    })
}

fn run_sql(node: &TopologyNode, sql: &str) {
    node.state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute_batch(sql)?;
            Ok(())
        })
        .unwrap();
}

/// The sealer serves only a checkpoint it adopted itself. A failed self-adoption refuses the
/// request with a retryable reason, and asking again for the unchanged state
/// adopts and serves it, then serves it again without growing the checkpoint rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_sealer_serves_only_a_checkpoint_it_adopted_and_an_unchanged_state_reuses_it() {
    use yadorilink_daemon::native_recovery::{DaemonRecovery, RecoveryPort};
    use yadorilink_replica_domain::protocol5::RefusalReason;

    setup();
    let a = device("seal-a", GROUP);
    let b = device("seal-b", GROUP);
    pair(&a, &b, GROUP).await;
    write(&a, "doc.txt", b"first");
    converge_to(&[&a, &b], &[("doc.txt", b"first")], "doc").await;
    converge_state(&[&a, &b], GROUP, "one native state").await;
    let group = FolderGroupId(GROUP.to_owned());

    run_sql(
        &a,
        "CREATE TRIGGER refuse_adoption BEFORE INSERT ON native_checkpoint_frontier \
         BEGIN SELECT RAISE(ABORT, 'adoption refused'); END;",
    );
    let refused = DaemonRecovery::with_private_seal_log_for_test(&a.state).serve(&group).await;
    assert_eq!(
        refused.err(),
        Some(RefusalReason::Overloaded),
        "a checkpoint the sealer could not adopt is not served"
    );
    assert_eq!(count_rows(&a, "native_checkpoints"), 0, "nothing was adopted");

    run_sql(&a, "DROP TRIGGER refuse_adoption;");
    let served = DaemonRecovery::with_private_seal_log_for_test(&a.state).serve(&group).await;
    assert!(served.is_ok(), "asking again for the same state adopts and serves it");
    let (checkpoints, frontier) =
        (count_rows(&a, "native_checkpoints"), count_rows(&a, "native_checkpoint_frontier"));
    assert_eq!(checkpoints, 1);
    for _ in 0..3 {
        let again = DaemonRecovery::with_private_seal_log_for_test(&a.state).serve(&group).await;
        assert!(again.is_ok());
    }
    assert_eq!(count_rows(&a, "native_checkpoints"), checkpoints, "no checkpoint row per ask");
    assert_eq!(count_rows(&a, "native_checkpoint_frontier"), frontier, "no frontier row per ask");
}

// --- the rebootstrap machine in real daemons ----------------------------------------------

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use yadorilink_daemon::native_rebootstrap::Point;
use yadorilink_daemon::preserved_items::{self, PreservedError, PreservedKind};
use yadorilink_sync_sqlite::native_rebootstrap::{
    group_frozen, rebootstrap_status, Failpoint, RebootstrapState,
};
use yadorilink_sync_sqlite::native_rebootstrap_replay::MachinePoint;

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.to_owned())
}

/// `a` and `b` agree on `kept.txt`; then `b` is cut off while `a` moves on and collects the
/// history `b` would need.
async fn lagging_pair(prefix: &str) -> (TopologyNode, TopologyNode) {
    let a = device(&format!("{prefix}-a"), GROUP);
    let b = device(&format!("{prefix}-b"), GROUP);
    pair(&a, &b, GROUP).await;
    write(&a, "kept.txt", b"kept");
    converge_to(&[&a, &b], &[("kept.txt", b"kept")], "initial").await;
    partition(&a, &b).await;
    for content in [&b"one"[..], b"two", b"three"] {
        write(&a, "doc.txt", content);
        captured(&a, GROUP).await;
    }
    assert!(collect_replication_log(&a, GROUP) > 0, "superseded deltas were collected");
    (a, b)
}

/// Writes `path` into `node`'s folder the moment its rebootstrap begins its final capture, so
/// the edit is on disk and in no index.
fn edit_when_the_rebootstrap_begins(
    node: &TopologyNode,
    path: &'static str,
    contents: &'static [u8],
) {
    let root = node.root.path().to_path_buf();
    let done = Arc::new(AtomicBool::new(false));
    node.state.set_rebootstrap_hook_for_test(Some(Arc::new(move |point| {
        if point == Point::Begin(Failpoint::BeforeCapture) && !done.swap(true, Ordering::SeqCst) {
            std::fs::write(root.join(path), contents).unwrap();
        }
        Ok(())
    })));
}

/// How many live heads `observer` holds at `path` written by `writer`'s current incarnation.
fn heads_of_current_incarnation(observer: &TopologyNode, writer: &TopologyNode, path: &str) -> i64 {
    use yadorilink_sync_sqlite::author_incarnation;
    let author = read(writer, author_incarnation::current_author);
    read(observer, |conn| {
        conn.query_row(
            "SELECT COUNT(*) FROM native_heads \
             WHERE group_id = ?1 AND path = ?2 AND author = ?3 AND incarnation = ?4",
            (GROUP, path, &author.device.0, &author.incarnation.0[..]),
            |row| row.get(0),
        )
        .map_err(Into::into)
    })
}

fn journal_state(node: &TopologyNode) -> Option<RebootstrapState> {
    read(node, |conn| rebootstrap_status(conn, &group())).map(|status| status.state)
}

/// Whether this platform refuses every rebootstrap (it cannot make a directory entry durable).
/// Decided by the capability the product itself consults, never by the target OS, so a platform
/// that gains the capability takes the success path of every test below unchanged.
fn rebootstrap_is_refused_here() -> bool {
    !yadorilink_sync_sqlite::native_rebootstrap_recovery::platform_supports_directory_durability()
}

/// The fail-closed contract of a platform that cannot rebootstrap, for a device `node` whose
/// peer `server` holds the state it lacks. Returns `false` at once where rebootstrap is
/// supported, and the caller runs its success path. Otherwise it offers `server`'s sealed state
/// to `node`, observes the explicit `DurabilityUnsupported` refusal, checks that nothing of
/// `node` changed (native state, files, journal, freeze), and returns `true`: the caller ends
/// there instead of waiting for a rebootstrap that cannot happen.
async fn rebootstrap_refused_and_state_intact(server: &TopologyNode, node: &TopologyNode) -> bool {
    use yadorilink_daemon::native_recovery::{DaemonRecovery, RecoveryPort};
    if !rebootstrap_is_refused_here() {
        return false;
    }
    let (state_before, files_before) = (native_state(node, GROUP), tree(node));
    let group = FolderGroupId(GROUP.to_owned());
    let bundle = DaemonRecovery::new(shared(server))
        .serve(&group)
        .await
        .expect("the up-to-date peer can seal its state");
    let node_state = shared(node).clone();
    let error = tokio::task::spawn_blocking(move || {
        DaemonRecovery::new(&node_state).apply(&group, &bundle)
    })
    .await
    .unwrap()
    .expect_err("a platform without directory durability must refuse the rebootstrap");
    assert!(error.contains("DurabilityUnsupported"), "{error}");
    assert_eq!(native_state(node, GROUP), state_before, "the refusal changed the native state");
    assert_eq!(tree(node), files_before, "the refusal changed the files");
    assert_eq!(journal_state(node), None, "a refused rebootstrap leaves no journal");
    assert!(!read(node, |conn| group_frozen(conn, GROUP)), "a refused rebootstrap freezes nothing");
    true
}

/// A user's edit that is on disk but in no index when the rebootstrap begins is folded into the
/// plan by its one final capture pass, authored under the freeze as the capture capability
/// allows, and replayed on top of the replacing state: it reaches the peer as an ordinary new
/// write.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_unsaved_edit_when_the_rebootstrap_begins_is_captured_and_replayed() {
    setup();
    let (a, b) = lagging_pair("capt").await;
    if rebootstrap_refused_and_state_intact(&a, &b).await {
        return;
    }
    edit_when_the_rebootstrap_begins(&b, "edit.txt", b"unsaved");

    pair(&a, &b, GROUP).await;

    let expected: &[(&str, &[u8])] =
        &[("kept.txt", b"kept"), ("doc.txt", b"three"), ("edit.txt", b"unsaved")];
    converge_to(&[&a, &b], expected, "the edit made at the freeze reached the group").await;
    assert_eq!(journal_state(&b), None, "the machine ended");
    assert_eq!(heads_of_current_incarnation(&a, &b, "edit.txt"), 1, "replayed once");
    assert!(!read(&b, |conn| group_frozen(conn, GROUP)));
}

/// A rebootstrap stopped after its install resumes from its journal when the device restarts:
/// the group stays frozen until then, the catch-up and the replay of the own edit run, and the
/// end state is the one an uninterrupted run reaches, the edit replayed once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_rebootstrap_stopped_before_its_replay_resumes_after_a_restart() {
    setup();
    let (a, b) = lagging_pair("resu").await;
    if rebootstrap_refused_and_state_intact(&a, &b).await {
        return;
    }
    let stopped = Arc::new(AtomicBool::new(false));
    let seen = stopped.clone();
    b.state.set_rebootstrap_hook_for_test(Some({
        let edit_root = b.root.path().to_path_buf();
        let wrote = Arc::new(AtomicBool::new(false));
        Arc::new(move |point| {
            if point == Point::Begin(Failpoint::BeforeCapture)
                && !wrote.swap(true, Ordering::SeqCst)
            {
                std::fs::write(edit_root.join("edit.txt"), b"unsaved").unwrap();
            }
            if point == Point::Machine(MachinePoint::BeforeReplaying)
                && !seen.swap(true, Ordering::SeqCst)
            {
                return Err(yadorilink_sync_sqlite::native_rebootstrap::Crash);
            }
            Ok(())
        })
    }));

    pair(&a, &b, GROUP).await;
    support::wait_until_with_context(
        || stopped.load(Ordering::SeqCst),
        CONVERGE,
        || "the rebootstrap never reached the stop point".to_owned(),
    )
    .await;

    assert_eq!(journal_state(&b), Some(RebootstrapState::CatchingUp));
    assert!(read(&b, |conn| group_frozen(conn, GROUP)), "the group stays frozen");
    assert!(!tree(&a).contains_key("edit.txt"), "nothing was replayed yet");

    let b = restart(b, &[&a], GROUP).await;

    let expected: &[(&str, &[u8])] =
        &[("kept.txt", b"kept"), ("doc.txt", b"three"), ("edit.txt", b"unsaved")];
    converge_to(&[&a, &b], expected, "the restarted device finished the rebootstrap").await;
    support::wait_until_with_context(
        || journal_state(&b).is_none(),
        CONVERGE,
        || format!("the journal still says {:?}", journal_state(&b)),
    )
    .await;
    assert_eq!(heads_of_current_incarnation(&a, &b, "edit.txt"), 1, "the edit was replayed once");
}

/// `c` last saw `x.txt`; its author removed it and collected the history, a new device `b`
/// recovered the author's state, and the author went away. `c` rebootstraps from `b`: the
/// version of `x.txt` it holds is not in the replacing state, so it is kept as an item.
async fn lagging_device_holding_a_version_the_group_dropped(
    prefix: &str,
) -> (TopologyNode, TopologyNode, TopologyNode) {
    let a = device(&format!("{prefix}-a"), GROUP);
    let c = device(&format!("{prefix}-c"), GROUP);
    pair(&a, &c, GROUP).await;
    write(&a, "x.txt", b"first");
    converge_to(&[&a, &c], &[("x.txt", b"first")], "initial").await;
    partition(&a, &c).await;
    remove(&a, "x.txt");
    captured(&a, GROUP).await;
    assert!(collect_replication_log(&a, GROUP) > 0);
    let b = device(&format!("{prefix}-b"), GROUP);
    pair(&b, &a, GROUP).await;
    converge_state(&[&a, &b], GROUP, "the new device recovered the author's state").await;
    partition(&a, &b).await;
    (a, b, c)
}

/// The version a rebootstrap would otherwise destroy is kept, listed with its content state,
/// restorable as one ordinary new write that replicates, and discardable: nothing else deletes
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_version_the_group_dropped_is_kept_listed_restored_and_discarded() {
    setup();
    let (_a, b, c) = lagging_device_holding_a_version_the_group_dropped("item").await;
    if rebootstrap_refused_and_state_intact(&b, &c).await {
        return;
    }
    pair(&c, &b, GROUP).await;
    converge_to(&[&b, &c], &[], "the lagging device caught up").await;

    let items = preserved_items::list(shared(&c)).await.unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    let item = &items[0];
    assert_eq!(
        (item.kind.clone(), item.path.as_str(), item.content.as_str(), item.group_removed),
        (PreservedKind::RemoteOnly, "x.txt", "complete", false)
    );
    let summary = preserved_items::summary(shared(&c));
    assert_eq!((summary.total, summary.content_unavailable, summary.bytes), (1, 0, 5));

    preserved_items::restore(shared(&c), GROUP, &item.item_id).await.unwrap();
    converge_to(&[&b, &c], &[("x.txt", b"first")], "the restored write replicated").await;
    assert_eq!(
        preserved_items::list(shared(&c)).await.unwrap().len(),
        1,
        "a restored item stays until it is discarded"
    );

    preserved_items::discard(shared(&c), GROUP, &item.item_id).await.unwrap();
    assert!(preserved_items::list(shared(&c)).await.unwrap().is_empty());
    assert!(matches!(
        preserved_items::discard(shared(&c), GROUP, &item.item_id).await,
        Err(PreservedError::NotFound)
    ));
}

/// A block of a version to preserve that is missing when the barrier is prepared is fetched from
/// a connected peer within the bounded attempt, and the item is complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_block_missing_at_the_barrier_is_fetched_from_a_peer() {
    setup();
    let (_a, b, c) = lagging_device_holding_a_version_the_group_dropped("fetch").await;
    if rebootstrap_refused_and_state_intact(&b, &c).await {
        return;
    }
    forget_block_after_the_final_capture(&c);

    pair(&c, &b, GROUP).await;
    converge_to(&[&b, &c], &[], "the lagging device caught up").await;

    let items = preserved_items::list(shared(&c)).await.unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(
        (items[0].content.as_str(), items[0].blocks_held, items[0].blocks_total),
        ("complete", 1, 1)
    );
}

/// The block of `x.txt` goes missing from `node` after its rebootstrap's final capture pass has
/// looked at the folder.
fn forget_block_after_the_final_capture(node: &TopologyNode) {
    let store = node.state.block_store.clone();
    node.state.set_rebootstrap_hook_for_test(Some(Arc::new(move |point| {
        if point == Point::Begin(Failpoint::AfterCapture) {
            let hash = store.put(b"first").unwrap();
            store.delete(&hash).unwrap();
        }
        Ok(())
    })));
}

/// An item whose bytes no peer holds is recorded as unavailable and never restorable; when the
/// missing blocks arrive it becomes complete, and then restores.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_item_without_all_its_blocks_completes_when_they_arrive() {
    setup();
    let (a, b, c) = lagging_device_holding_a_version_the_group_dropped("part").await;
    if rebootstrap_refused_and_state_intact(&b, &c).await {
        return;
    }
    let hash = a.state.block_store.put(b"first").unwrap();
    a.state.block_store.delete(&hash).unwrap();
    forget_block_after_the_final_capture(&c);

    pair(&c, &b, GROUP).await;
    converge_to(&[&b, &c], &[], "the lagging device caught up").await;

    let items = preserved_items::list(shared(&c)).await.unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(
        (items[0].content.as_str(), items[0].blocks_held, items[0].blocks_total),
        ("unavailable", 0, 1)
    );
    assert_eq!(preserved_items::summary(shared(&c)).content_unavailable, 1);
    assert!(matches!(
        preserved_items::restore(shared(&c), GROUP, &items[0].item_id).await,
        Err(PreservedError::ContentUnavailable)
    ));

    // The blocks arrive, by whatever means.
    c.state.block_store.put(b"first").unwrap();
    preserved_items::complete_unavailable_items(shared(&c), &group()).await;

    let items = preserved_items::list(shared(&c)).await.unwrap();
    assert_eq!(items[0].content, "complete");
    preserved_items::restore(shared(&c), GROUP, &items[0].item_id).await.unwrap();
    converge_to(&[&b, &c], &[("x.txt", b"first")], "the completed item restored").await;
}

/// Removing a group keeps its items: they are listed under their removed group, cannot be
/// restored without a group to write to, and are deleted only by an explicit discard.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn items_of_a_removed_group_are_kept_listed_and_discardable() {
    setup();
    let (_a, b, c) = lagging_device_holding_a_version_the_group_dropped("gone").await;
    if rebootstrap_refused_and_state_intact(&b, &c).await {
        return;
    }
    pair(&c, &b, GROUP).await;
    converge_to(&[&b, &c], &[], "the lagging device caught up").await;
    let item_id = preserved_items::list(shared(&c)).await.unwrap()[0].item_id.clone();

    let local_path = c.root.path().to_string_lossy().to_string();
    c.state.replica_coordinator.link_repository().remove_link(&local_path).unwrap();

    let items = preserved_items::list(shared(&c)).await.unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0].group_removed);
    assert!(matches!(
        preserved_items::restore(shared(&c), GROUP, &item_id).await,
        Err(PreservedError::NotAWriter)
    ));
    preserved_items::discard(shared(&c), GROUP, &item_id).await.unwrap();
    assert!(preserved_items::list(shared(&c)).await.unwrap().is_empty());
}

/// A device that is no longer a writer replays nothing: its own unsaved edit is moved out of the
/// folder into the recovery area, never reaches the group, and is listed as an own change that
/// was set aside.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn own_changes_a_viewer_cannot_replay_are_set_aside_and_listed() {
    setup();
    let (a, b) = lagging_pair("view").await;
    if rebootstrap_refused_and_state_intact(&a, &b).await {
        return;
    }
    // The device loses its write role the moment its rebootstrap begins.
    let (states, device) = (vec![a.state.clone(), b.state.clone()], b.device_id.clone());
    let root = b.root.path().to_path_buf();
    let done = Arc::new(AtomicBool::new(false));
    b.state.set_rebootstrap_hook_for_test(Some(Arc::new(move |point| {
        if point == Point::Begin(Failpoint::BeforeCapture) && !done.swap(true, Ordering::SeqCst) {
            demote_to_viewer_on(&states, GROUP, &device);
            std::fs::write(root.join("edit.txt"), b"unsaved").unwrap();
        }
        Ok(())
    })));

    pair(&a, &b, GROUP).await;

    converge_to(&[&a, &b], &[("kept.txt", b"kept"), ("doc.txt", b"three")], "the viewer caught up")
        .await;
    assert_eq!(journal_state(&b), None);
    assert!(!tree(&a).contains_key("edit.txt"), "a viewer's change never reaches the group");
    let items = preserved_items::list(shared(&b)).await.unwrap();
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0].kind, PreservedKind::OwnUnit);
    assert_eq!(items[0].paths, vec!["edit.txt".to_owned()]);
    assert!(items[0].originals_quarantined, "the original left the folder");
    assert_eq!(preserved_items::summary(shared(&b)).unreplayed_own_units, 1);
}

/// A held own unit is retried through the public surface: refused while the device is still a
/// viewer, authored through the replay once it is a writer again, and gone from the list.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_held_own_unit_is_retried_once_the_device_is_a_writer_again() {
    setup();
    let (a, b) = lagging_pair("retry").await;
    if rebootstrap_refused_and_state_intact(&a, &b).await {
        return;
    }
    let (states, device) = (vec![a.state.clone(), b.state.clone()], b.device_id.clone());
    let root = b.root.path().to_path_buf();
    let done = Arc::new(AtomicBool::new(false));
    b.state.set_rebootstrap_hook_for_test(Some(Arc::new(move |point| {
        if point == Point::Begin(Failpoint::BeforeCapture) && !done.swap(true, Ordering::SeqCst) {
            demote_to_viewer_on(&states, GROUP, &device);
            std::fs::write(root.join("edit.txt"), b"unsaved").unwrap();
        }
        Ok(())
    })));
    pair(&a, &b, GROUP).await;
    converge_to(&[&a, &b], &[("kept.txt", b"kept"), ("doc.txt", b"three")], "the viewer caught up")
        .await;
    let unit = preserved_items::list(shared(&b)).await.unwrap().remove(0);
    assert_eq!(unit.kind, PreservedKind::OwnUnit);

    assert!(matches!(
        preserved_items::retry(shared(&b), GROUP, &unit.item_id).await,
        Err(PreservedError::NotAWriter)
    ));
    assert_eq!(preserved_items::list(shared(&b)).await.unwrap().len(), 1, "still held");

    grant_writers(&[&a, &b], GROUP);
    preserved_items::retry(shared(&b), GROUP, &unit.item_id).await.unwrap();

    assert!(preserved_items::list(shared(&b)).await.unwrap().is_empty(), "resolved");
    converge_to(
        &[&a, &b],
        &[("kept.txt", b"kept"), ("doc.txt", b"three"), ("edit.txt", b"unsaved")],
        "the retried change reached the group",
    )
    .await;
    assert!(matches!(
        preserved_items::retry(shared(&b), GROUP, &unit.item_id).await,
        Err(PreservedError::NotFound)
    ));
}
