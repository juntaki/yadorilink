//! Native replication in real daemons: two devices, real sessions over
//! loopback, real (fake-plane) checkpoints. Nothing here feeds native from
//! DCF: a remote head reaches a device's `NativeState` only as a signed
//! delta over the native-replication ALPN.

mod native_e2e_support;
mod support;

use native_e2e_support::*;
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_sync_sqlite::{native_projection_binding, native_replication, native_store};

const GROUP: &str = "native-e2e-group";

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

async fn two() -> (TopologyNode, TopologyNode) {
    let a = device("nat-a", GROUP);
    let b = device("nat-b", GROUP);
    pair(&a, &b, GROUP).await;
    (a, b)
}

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.to_string())
}

fn roots(node: &TopologyNode) -> native_replication::SummaryRoots {
    read(node, |conn| native_replication::summary_roots(conn, &group()))
}

fn native_head_count(node: &TopologyNode, path: &str) -> usize {
    read(node, |conn| {
        Ok(native_store::native_heads_at(
            conn,
            &group(),
            &yadorilink_replica_domain::ids::SyncPath(path.to_string()),
        )?
        .len())
    })
}

fn placement_of(
    node: &TopologyNode,
    path: &str,
) -> Option<native_projection_binding::NativePhysicalIdentity> {
    read(node, |conn| native_projection_binding::resolve_native_physical_path(conn, GROUP, path))
}

async fn native_converged(a: &TopologyNode, b: &TopologyNode, what: &str) {
    support::wait_until_with_context(
        || roots(a) == roots(b),
        std::time::Duration::from_secs(60),
        || format!("{what}: {:?} vs {:?}", roots(a), roots(b)),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_remote_write_reaches_the_peers_native_state() {
    setup();
    let (a, b) = two().await;
    assert!(
        a.state.native_replication_attached_for_test(&b.device_id)
            || b.state.native_replication_attached_for_test(&a.device_id)
    );

    write(&a, "note.txt", b"from a");
    captured(&a, GROUP).await;
    converge_to(&[&a, &b], &[("note.txt", b"from a")], "the file syncs").await;

    native_converged(&a, &b, "native state follows").await;
    assert_eq!(
        native_head_count(&b, "note.txt"),
        1,
        "b's native state holds a's head, received as a delta"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writes_leave_both_heads_and_a_placed_conflict_copy_on_both_devices() {
    setup();
    let (a, b) = two().await;
    write(&a, "c.txt", b"base");
    converge_to(&[&a, &b], &[("c.txt", b"base")], "base").await;
    partition(&a, &b).await;
    write(&a, "c.txt", b"from a");
    write(&b, "c.txt", b"from b");
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    pair(&a, &b, GROUP).await;
    let tree = converge_where(&[&a, &b], "a conflict copy appears", |tree| {
        conflict_copies(tree).len() == 1
    })
    .await;
    let copy = conflict_copies(&tree).remove(0);

    native_converged(&a, &b, "native state converges").await;
    // Placements are settled just after each delta is admitted.
    support::wait_until_with_context(
        || [&a, &b].iter().all(|node| placement_of(node, &copy).is_some()),
        std::time::Duration::from_secs(30),
        || format!("native places {copy} on both devices"),
    )
    .await;

    for node in [&a, &b] {
        assert_eq!(
            native_head_count(node, "c.txt"),
            2,
            "{}: both concurrent heads",
            node.device_id
        );
        let placed = placement_of(node, &copy);
        let placed = placed.unwrap_or_else(|| {
            let dump = read(node, |conn| {
                let placements = yadorilink_sync_sqlite::stable_projection_binding::native_placements(conn, GROUP)?;
                let heads = native_store::native_heads_at(
                    conn,
                    &group(),
                    &yadorilink_replica_domain::ids::SyncPath("c.txt".into()),
                )?;
                let rows: Option<(bool, i64)> = conn
                    .query_row(
                        "SELECT deleted, size FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                        [GROUP, copy.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .ok();
                Ok(format!("placements {placements:?}\nheads {heads:?}\nrow {rows:?}"))
            });
            panic!("{}: native resolves the conflict copy {copy}\n{dump}", node.device_id)
        });
        assert_eq!(placed.source_path.as_str(), "c.txt");
    }
}

/// Deleting a conflict copy removes its content's heads and the copy on every
/// device, whichever device wrote it: the delta names the source path, so the
/// peers find the copy through the placement the source still has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_conflict_copy_removes_it_on_both_devices() {
    setup();
    let (a, b) = two().await;
    write(&a, "c.txt", b"base");
    converge_to(&[&a, &b], &[("c.txt", b"base")], "base").await;
    partition(&a, &b).await;
    write(&a, "c.txt", b"from a");
    write(&b, "c.txt", b"from b");
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    pair(&a, &b, GROUP).await;
    let tree = converge_where(&[&a, &b], "a conflict copy appears", |tree| {
        conflict_copies(tree).len() == 1
    })
    .await;
    let copy = conflict_copies(&tree).remove(0);
    let kept = tree["c.txt"].clone();
    remove(&b, &copy);
    converge_to(&[&a, &b], &[("c.txt", &kept)], "the copy is gone everywhere").await;
    native_converged(&a, &b, "native state converges").await;
    for node in [&a, &b] {
        assert_eq!(
            native_head_count(node, "c.txt"),
            1,
            "{}: the copy's head is gone",
            node.device_id
        );
    }
}

/// Unlinking drops only the link row. Linking the same folder again keeps the
/// replica's history, and what changed on disk meanwhile is authored as new
/// changes of this device that are concurrent with whatever the peer did that
/// this replica had not seen: a delete never removes a put it did not observe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relinking_after_unlink_authors_local_differences_as_concurrent_changes() {
    use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;

    setup();
    let (a, b) = two().await;
    write(&a, "x.txt", b"x0");
    write(&a, "z.txt", b"z0");
    converge_to(&[&a, &b], &[("x.txt", b"x0"), ("z.txt", b"z0")], "base").await;
    let a_versions_of_x =
        || a.state.replica_coordinator.sqlite().dag_list_versions(GROUP, "x.txt").unwrap();
    let versions_before = a_versions_of_x();
    assert!(!versions_before.is_empty());

    // Unlink A: the watcher stops and only the links row goes.
    let a_path = a.root.path().to_string_lossy().to_string();
    LinkRuntimeController::new(a.state.clone()).stop(&a_path).await;
    a.state.replica_coordinator.link_repository().remove_link(&a_path).unwrap();

    // While A is unlinked: A deletes x, edits z and creates w on disk; B, which
    // never saw any of that, edits x, adds y and edits z.
    remove(&a, "x.txt");
    write(&a, "z.txt", b"z-from-a");
    write(&a, "w.txt", b"w-from-a");
    write(&b, "x.txt", b"x1");
    write(&b, "y.txt", b"y-from-b");
    write(&b, "z.txt", b"z-from-b");
    captured(&b, GROUP).await;

    // Relink the same folder and reconnect.
    link_eager(&a, GROUP);
    pair(&a, &b, GROUP).await;
    let tree = converge_where(&[&a, &b], "the unlinked-time changes merge", |tree| {
        tree.get("w.txt").is_some()
            && tree.get("y.txt").is_some()
            && conflict_copies(tree).len() == 1
    })
    .await;
    captured(&a, GROUP).await;
    native_converged(&a, &b, "native state converges").await;

    assert_eq!(tree["x.txt"], b"x1", "B's unobserved new version of x survives A's delete");
    assert_eq!(tree["y.txt"], b"y-from-b", "B's new file arrives");
    assert_eq!(tree["w.txt"], b"w-from-a", "A's new file syncs");
    let z_copy = conflict_copies(&tree).remove(0);
    let mut z_versions = [tree["z.txt"].clone(), tree[&z_copy].clone()];
    z_versions.sort();
    assert_eq!(
        z_versions,
        [b"z-from-a".to_vec(), b"z-from-b".to_vec()],
        "both concurrent edits of z are preserved"
    );
    assert_eq!(
        native_head_count(&a, "x.txt"),
        1,
        "A's delete removed only the head it had observed"
    );

    // A's history survived the unlink and relink: every version of x it
    // recorded before is still listed (its state moves on, its content hash
    // does not).
    let after: Vec<_> = a_versions_of_x().into_iter().map(|v| v.version_hash).collect();
    for kept in &versions_before {
        assert!(
            after.contains(&kept.version_hash),
            "a version of x recorded before the unlink is gone"
        );
    }
    assert!(after.len() > versions_before.len(), "the new versions are recorded beside the old");
}
