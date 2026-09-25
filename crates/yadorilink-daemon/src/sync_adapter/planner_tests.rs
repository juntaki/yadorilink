//! Gates for planning outside the writer gate.
//!
//! The retroactive planner used to run inside the same IMMEDIATE transaction
//! as its emission, which put a traversal of the whole frontier-reachable DAG
//! under the process-wide writer gate. It was measured holding that gate for
//! 366 of one 348-second window across 46 passes, and independently as the
//! dominant writer-gate consumer by a 5-7x margin, up to ~2180s cumulative in
//! one run. These pin that it no longer needs the gate at all, and that the
//! invariant the gate used to provide is now checked explicitly instead.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::change::{Change, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::dag_store;
use yadorilink_sync_sqlite::retroactive_conflict::{
    plan_retroactive_merge, PlanStaleness, RetroactiveMergeOutcome,
};
use yadorilink_sync_sqlite::SyncSqliteError;

const GROUP: &str = "g";
const PATH: &str = "shared.bin";

fn db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            dag_store::init_conflict_copy_provenance_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            dag_store::init_dag_schema(conn)
                .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))
        })
        .unwrap(),
    )
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn version(mtime: i64) -> FileVersion {
    FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn put_at(
    path: &str,
    parents: Vec<ChangeHash>,
    lamport: u64,
    device: &str,
    version: &FileVersion,
    signing_key: &SigningKey,
) -> Change {
    create_signed_for_tests(
        parents,
        lamport,
        DeviceId(device.to_string()),
        FolderGroupId(GROUP.to_string()),
        vec![Op::Put {
            path: SyncPath(path.to_string()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }],
        signing_key,
    )
}

/// A forked history with one outstanding conflict-copy obligation.
/// Returns the tip Change and its Lamport value, which a later change must
/// use as its `max_parent_lamport`.
fn seed_forked_history(db: &SyncDatabase) -> (ChangeHash, u64) {
    db.write(|conn| {
        let root_version = version(1);
        let a_version = version(2);
        let b_version = version(3);
        let d_version = version(4);
        for value in [&root_version, &a_version, &b_version, &d_version] {
            dag_store::put_file_version(conn, GROUP, value)?;
        }

        let root = put_at(PATH, Vec::new(), 0, "root", &root_version, &key(9));
        dag_store::admit_change(conn, &root)?;
        let a =
            put_at(PATH, vec![root.compute_hash()], root.lamport, "device-a", &a_version, &key(1));
        dag_store::admit_change(conn, &a)?;
        let d = put_at(PATH, vec![a.compute_hash()], a.lamport, "device-d", &d_version, &key(4));
        dag_store::admit_change(conn, &d)?;
        let b =
            put_at(PATH, vec![root.compute_hash()], root.lamport, "device-b", &b_version, &key(2));
        dag_store::admit_change(conn, &b)?;

        Ok::<_, SyncSqliteError>((d.compute_hash(), d.lamport))
    })
    .unwrap()
}

/// Hold the writer gate until released.
fn latch_the_writer(db: Arc<SyncDatabase>) -> (Arc<AtomicUsize>, std::thread::JoinHandle<()>) {
    let release = Arc::new(AtomicUsize::new(0));
    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();

    let holder = {
        let release = release.clone();
        std::thread::spawn(move || {
            let mut announced = false;
            let _ = db.write(|conn| {
                conn.execute_batch("CREATE TABLE IF NOT EXISTS writer_latch (x INTEGER)")?;
                if !announced {
                    let _ = held_tx.send(());
                    announced = true;
                }
                while release.load(Ordering::SeqCst) == 0 {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok::<_, SyncSqliteError>(())
            });
        })
    };

    held_rx.recv().expect("writer latch engaged");
    (release, holder)
}

/// Gate: planning completes with the writer gate held by someone else.
///
/// This is the whole point of the change. While planning ran inside the
/// emission's own IMMEDIATE transaction it could not even begin until every
/// other writer had finished, and once begun it excluded all of them for the
/// duration of a full DAG traversal.
#[test]
fn planning_completes_while_another_writer_holds_the_gate() {
    let db = db();
    let _ = seed_forked_history(&db);

    let (release, holder) = latch_the_writer(db.clone());

    let outcome = db
        .read_snapshot::<_, SyncSqliteError>(|conn| plan_retroactive_merge(conn, GROUP))
        .expect("planning must not need the writer gate");

    let RetroactiveMergeOutcome::Plan(plan) = outcome else {
        panic!("expected a plan");
    };
    assert_eq!(plan.source_paths, vec![PATH.to_string()]);
    assert!(!plan.obligations.is_empty());

    release.store(1, Ordering::SeqCst);
    holder.join().unwrap();
}

/// Gate: planning sees one snapshot, whatever lands while it runs.
///
/// `SyncDatabase::read` opens no transaction, so a plan built through it can
/// observe a different database between one statement and the next — a plan
/// describing a state that never existed at any instant. Admissions from
/// another thread throughout the traversal must not produce a mixed view, a
/// panic, or a plan naming something that was never simultaneously true.
#[test]
fn planning_is_unaffected_by_admissions_landing_throughout_it() {
    let db = db();
    let (tip, tip_lamport) = seed_forked_history(&db);

    let stop = Arc::new(AtomicUsize::new(0));
    let admitter = {
        let db = db.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut parent = tip;
            let mut lamport = tip_lamport;
            let mut mtime = 100i64;
            while stop.load(Ordering::SeqCst) == 0 {
                let value = version(mtime);
                let change =
                    put_at("churn.bin", vec![parent], lamport, "device-churn", &value, &key(5));
                let admitted = db.write(|conn| {
                    dag_store::put_file_version(conn, GROUP, &value)?;
                    dag_store::admit_change(conn, &change)?;
                    Ok::<_, SyncSqliteError>(())
                });
                if admitted.is_err() {
                    break;
                }
                parent = change.compute_hash();
                lamport += 1;
                mtime += 1;
            }
        })
    };

    // Plan repeatedly while history churns underneath.
    for _ in 0..25 {
        let outcome = db
            .read_snapshot::<_, SyncSqliteError>(|conn| plan_retroactive_merge(conn, GROUP))
            .expect("planning must survive concurrent admission");

        if let RetroactiveMergeOutcome::Plan(plan) = outcome {
            // Whatever frontier this plan saw, it is internally consistent:
            // the plan names an obligation only if it named the path too.
            if !plan.obligations.is_empty() {
                assert!(
                    !plan.source_paths.is_empty(),
                    "a plan with obligations must name the paths they came from"
                );
            }
        }
    }

    stop.store(1, Ordering::SeqCst);
    admitter.join().unwrap();
}

/// Gate: a plan is never reused across a frontier change.
///
/// Committing a stale plan is the corruption this design has to rule out — a
/// stale winner reasserted with a newer Lamport timestamp. The plan reports
/// its own staleness rather than relying on the caller to remember.
#[test]
fn a_plan_reports_its_own_staleness_after_history_moves() {
    let db = db();
    let (tip, tip_lamport) = seed_forked_history(&db);

    let plan = match db
        .read_snapshot::<_, SyncSqliteError>(|conn| plan_retroactive_merge(conn, GROUP))
        .unwrap()
    {
        RetroactiveMergeOutcome::Plan(plan) => plan,
        other => panic!("expected a plan, got {other:?}"),
    };

    db.read_snapshot::<_, SyncSqliteError>(|conn| {
        assert_eq!(plan.revalidate(conn, GROUP)?, None, "fresh plan must be committable");
        Ok(())
    })
    .unwrap();

    // History advances.
    db.write(|conn| {
        let value = version(500);
        dag_store::put_file_version(conn, GROUP, &value)?;
        let change = put_at("after.bin", vec![tip], tip_lamport, "device-late", &value, &key(6));
        dag_store::admit_change(conn, &change)?;
        Ok::<_, SyncSqliteError>(())
    })
    .unwrap();

    db.read_snapshot::<_, SyncSqliteError>(|conn| {
        assert_eq!(
            plan.revalidate(conn, GROUP)?,
            Some(PlanStaleness::FrontierMoved),
            "a plan built against a frontier that has moved must refuse itself"
        );
        Ok(())
    })
    .unwrap();
}
