#![cfg(test)]

//! `MaterializeToTemp` over the shell connection's message handling: complete-or-nothing
//! handoffs, the version rules, the fence, cancellation by request id, and the ledger entry that
//! only a delivered response may leave.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, Notify};
use yadorilink_ipc_proto::shellipc::MaterializeToTempResponse;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_sync_sqlite::provider_provenance::Served;

use crate::daemon_state::DaemonState;
use crate::provider_handoff::HandoffRoot;
use crate::shell_ipc::provider_tests::{domain_state, handshake, send, state_with_root};

use super::*;

const GROUP: &str = "group-1";

struct Fx {
    state: Arc<DaemonState>,
    root: String,
    context: Arc<ShellContext>,
    requests: MaterializeRequests,
    tx: Reply,
    rx: mpsc::UnboundedReceiver<Delivery>,
    dir: tempfile::TempDir,
}

fn data_of(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|n| (n as u8).wrapping_mul(31).wrapping_add(tag)).collect()
}

impl Fx {
    async fn with_lifetime(lifetime: Duration) -> Self {
        let (state, root) = state_with_root();
        let root_id = hex::decode(&root).unwrap();
        send(&state, domain_state(&root_id, true)).await;
        send(&state, handshake(&root_id)).await;
        let dir = tempfile::tempdir().unwrap();
        let handoff = HandoffRoot::open_with_lifetime(dir.path(), lifetime).unwrap();
        let context =
            Arc::new(ShellContext::from_state(state.clone()).with_handoff_root(Some(handoff)));
        let (tx, rx) = mpsc::unbounded_channel();
        Self { state, root, context, requests: MaterializeRequests::default(), tx, rx, dir }
    }

    async fn new() -> Self {
        Self::with_lifetime(Duration::from_secs(60)).await
    }

    fn repo(&self) -> &yadorilink_sync_sqlite::provider::ProviderRepository {
        self.state.replica_coordinator.provider_repository()
    }

    fn staging(&self) -> std::path::PathBuf {
        self.dir.path().join("staging")
    }

    fn handoff_dir(&self) -> std::path::PathBuf {
        self.dir.path().join("handoff")
    }

    /// Commits a version of `path` whose bytes are `data` (one block, present in the store with
    /// this group's provenance).
    fn commit(&self, path: &str, seq: i64, data: &[u8]) {
        let hash = self.state.block_store.put(data).unwrap();
        let hash_bytes = hex::decode(&hash).unwrap();
        self.state
            .replica_coordinator
            .record_block_provenance(GROUP, std::slice::from_ref(&hash_bytes))
            .unwrap();
        let blocks = format!(r#"[{{"hash":{:?},"offset":0,"size":{}}}]"#, hash_bytes, data.len());
        self.state
            .replica_coordinator
            .database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                tx.execute(
                    "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![GROUP, path],
                )?;
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state) VALUES (?1, ?2, ?3, 1, ?5, 0, ?4, 'current')",
                    rusqlite::params![GROUP, path, data.len() as i64, seq, blocks],
                )?;
                let row = yadorilink_sync_sqlite::read_canonical_current_row(tx, GROUP, path)?
                    .expect("the row just written");
                let version = yadorilink_replica_domain::session_state::CurrentVersionRecord::from(
                    row.snapshot,
                )
                .to_file_version();
                yadorilink_sync_sqlite::dag_store::put_file_version(tx, GROUP, &version)?;
                Ok(())
            })
            .unwrap();
    }

    /// An item the OS was already shown at its current version (so a newer content version is
    /// pending behind the fence until it is published).
    fn published_item(&self, path: &str, data: &[u8]) -> ItemId {
        self.commit(path, 1, data);
        let item = self.repo().mint_item(&self.root, path).unwrap();
        self.repo().publish_first(&self.root, &item, self.current_hash(&item)).unwrap();
        item
    }

    /// An item the OS was never shown: nothing is published yet, so the fence is not on.
    fn unpublished_item(&self, path: &str, data: &[u8]) -> ItemId {
        self.commit(path, 1, data);
        self.repo().mint_item(&self.root, path).unwrap()
    }

    fn request(&self, id: &[u8], item: &ItemId, requested: &[u8]) {
        let message = ShellIpcMessage {
            payload: Some(Payload::MaterializeToTempRequest(MaterializeToTempRequest {
                request_id: id.to_vec(),
                root_id: hex::decode(&self.root).unwrap(),
                item_id: item.to_vec(),
                requested_version_hash: requested.to_vec(),
            })),
        };
        assert!(materialize_message(&self.context, &self.requests, &self.tx, &message));
    }

    fn cancel(&self, id: &[u8]) {
        let message = ShellIpcMessage {
            payload: Some(Payload::MaterializeCancel(MaterializeCancel {
                request_id: id.to_vec(),
            })),
        };
        assert!(materialize_message(&self.context, &self.requests, &self.tx, &message));
    }

    /// The next outgoing delivery, not yet acknowledged to its sender.
    async fn delivery(&mut self) -> Delivery {
        tokio::time::timeout(Duration::from_secs(10), self.rx.recv())
            .await
            .expect("no response")
            .expect("the channel closed")
    }

    /// The next response, with the socket write reported as completed.
    async fn response(&mut self) -> MaterializeToTempResponse {
        let delivery = self.delivery().await;
        if let Some(written) = delivery.written {
            let _ = written.send(true);
        }
        match delivery.message.payload {
            Some(Payload::MaterializeToTempResponse(response)) => response,
            other => panic!("expected a response, got {other:?}"),
        }
    }

    async fn ask(&mut self, id: &[u8], item: &ItemId) -> MaterializeToTempResponse {
        self.request(id, item, &[]);
        self.response().await
    }

    fn handoff_names(&self) -> Vec<String> {
        names_in(&self.handoff_dir())
    }

    fn current_hash(&self, item: &ItemId) -> VersionHash {
        self.repo().current_version_hash(&self.root, item).unwrap().unwrap()
    }
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn set_hook(path: &str, hook: crate::hydration::AssembledHookFn) {
    crate::hydration::ASSEMBLED_HOOKS
        .lock()
        .unwrap()
        .get_or_insert_with(Default::default)
        .insert(format!("{GROUP}/{path}"), hook);
}

fn failure(response: &MaterializeToTempResponse) -> MaterializeFailure {
    MaterializeFailure::try_from(response.failure).unwrap()
}

/// The current version arrives as a complete file under a plain name, with nothing left in
/// staging, and the item's row goes back to the state it was in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_current_version_is_handed_over_as_one_complete_verified_file() {
    let mut fx = Fx::new().await;
    let data = data_of(1, 300_000);
    let item = fx.published_item("a.bin", &data);
    let before = fx
        .state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(GROUP, "a.bin")
        .unwrap();

    let response = fx.ask(b"req-1", &item).await;
    assert!(response.ok, "{}", response.error);
    assert!(response.handoff_name.starts_with(&hex::encode(b"req-1")), "{}", response.handoff_name);
    assert_eq!(response.version_hash, fx.current_hash(&item).0.to_vec());
    assert_eq!(response.size, data.len() as u64);
    assert_eq!(fx.handoff_names(), std::slice::from_ref(&response.handoff_name));
    assert_eq!(std::fs::read(fx.handoff_dir().join(&response.handoff_name)).unwrap(), data);
    assert!(names_in(&fx.staging()).is_empty(), "staging was not cleaned");
    assert_eq!(
        fx.state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, "a.bin")
            .unwrap(),
        before,
        "the row did not return to its state"
    );
    // The handoff is recorded once the response is out.
    eventually("the handoff ledger entry", || {
        fx.repo()
            .handoff(&fx.root, &item)
            .unwrap()
            .is_some_and(|h| h.version_hash == fx.current_hash(&item))
    })
    .await;
}

/// A file is in `handoff/` only when it is complete: while the bytes are being assembled and
/// verified they exist only in `staging/` (and there complete, never half written when named),
/// and nothing is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_partial_file_is_never_visible_in_the_handoff_directory() {
    let mut fx = Fx::new().await;
    let data = data_of(2, 200_000);
    let item = fx.published_item("partial.bin", &data);
    let (staging, handoff) = (fx.staging(), fx.handoff_dir());
    let observed = Arc::new(Mutex::new(None));
    {
        let observed = observed.clone();
        set_hook(
            "partial.bin",
            Arc::new(move |assembled: &Path| {
                let snapshot = (
                    names_in(&handoff),
                    assembled.parent().map(Path::to_path_buf),
                    std::fs::metadata(assembled).map(|m| m.len()).ok(),
                );
                let staged_here = names_in(&staging);
                *observed.lock().unwrap() = Some((snapshot, staged_here));
                Box::pin(async {})
            }),
        );
    }
    let response = fx.ask(b"req-p", &item).await;
    assert!(response.ok, "{}", response.error);
    let ((handoff_seen, parent, len), staged) =
        observed.lock().unwrap().take().expect("the hook ran");
    assert!(handoff_seen.is_empty(), "something was in handoff/ during assembly: {handoff_seen:?}");
    assert_eq!(parent.as_deref(), Some(fx.staging().as_path()));
    assert_eq!(len, Some(data.len() as u64), "the staged file was not complete when verified");
    assert_eq!(staged.len(), 1);
    assert_eq!(fx.handoff_names().len(), 1);
}

/// Bytes that fail verification never reach the handoff directory or the ledger.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bytes_that_fail_verification_are_never_handed_over() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("bad.bin", &data_of(3, 50_000));
    set_hook(
        "bad.bin",
        Arc::new(|assembled: &Path| {
            let file = std::fs::OpenOptions::new().write(true).open(assembled).unwrap();
            file.set_len(10).unwrap();
            Box::pin(async {})
        }),
    );
    let response = fx.ask(b"req-b", &item).await;
    assert!(!response.ok);
    assert_eq!(failure(&response), MaterializeFailure::Unobtainable);
    assert!(response.handoff_name.is_empty());
    assert!(fx.handoff_names().is_empty());
    assert!(names_in(&fx.staging()).is_empty());
    assert!(fx.repo().handoff(&fx.root, &item).unwrap().is_none());
}

/// A version named by the request that is not current is out of date, and an update that lands
/// while the bytes are being assembled never reaches the OS as the old version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_version_that_is_not_current_is_out_of_date() {
    let mut fx = Fx::new().await;
    let item = fx.unpublished_item("named.bin", &data_of(4, 40_000));
    let v1 = fx.current_hash(&item);
    fx.commit("named.bin", 2, &data_of(5, 41_000));

    fx.request(b"req-n1", &item, &v1.0);
    let response = fx.response().await;
    assert!(!response.ok);
    assert_eq!(failure(&response), MaterializeFailure::VersionOutOfDate);
    assert!(fx.handoff_names().is_empty());

    // The same, with the update landing during the assembly.
    let item = fx.unpublished_item("mid.bin", &data_of(6, 40_000));
    let v1 = fx.current_hash(&item);
    let state = fx.state.clone();
    let committed = Arc::new(AtomicBool::new(false));
    {
        let (state, root, committed) = (state, fx.root.clone(), committed.clone());
        set_hook(
            "mid.bin",
            Arc::new(move |_: &Path| {
                if !committed.swap(true, Ordering::SeqCst) {
                    let fx = Fx::over(&state, &root);
                    fx.commit("mid.bin", 2, &data_of(7, 42_000));
                }
                Box::pin(async {})
            }),
        );
    }
    fx.request(b"req-n2", &item, &v1.0);
    let response = fx.response().await;
    assert!(!response.ok);
    assert_eq!(failure(&response), MaterializeFailure::VersionOutOfDate);
    assert!(fx.handoff_names().is_empty(), "old bytes were handed over");
    assert!(names_in(&fx.staging()).is_empty());
    assert!(fx.repo().handoff(&fx.root, &item).unwrap().is_none());
}

/// Without a named version, an update during the assembly restarts it on the latest version: the
/// bytes returned are the latest's, with the latest's hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_update_during_assembly_restarts_on_the_latest_version() {
    let mut fx = Fx::new().await;
    let item = fx.unpublished_item("restart.bin", &data_of(8, 40_000));
    let latest = data_of(9, 43_000);
    let committed = Arc::new(AtomicBool::new(false));
    {
        let (state, root, committed, latest) =
            (fx.state.clone(), fx.root.clone(), committed.clone(), latest.clone());
        set_hook(
            "restart.bin",
            Arc::new(move |_: &Path| {
                if !committed.swap(true, Ordering::SeqCst) {
                    Fx::over(&state, &root).commit("restart.bin", 2, &latest);
                }
                Box::pin(async {})
            }),
        );
    }
    let response = fx.ask(b"req-r", &item).await;
    assert!(response.ok, "{}", response.error);
    assert_eq!(response.version_hash, fx.current_hash(&item).0.to_vec());
    assert_eq!(std::fs::read(fx.handoff_dir().join(&response.handoff_name)).unwrap(), latest);
    assert!(names_in(&fx.staging()).is_empty());
}

/// An item whose newer content is not yet published is behind the fence: nothing is assembled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_publication_refuses_the_fetch() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("fenced.bin", &data_of(10, 30_000));
    fx.commit("fenced.bin", 2, &data_of(11, 31_000));
    let response = fx.ask(b"req-f", &item).await;
    assert!(!response.ok);
    assert_eq!(failure(&response), MaterializeFailure::PublicationPending);
    assert!(fx.handoff_names().is_empty());
    assert!(names_in(&fx.staging()).is_empty());
    assert!(fx.repo().handoff(&fx.root, &item).unwrap().is_none());
}

/// A cancel aborts exactly the request it names: its temp file is removed, its row reverts, the
/// canceller is answered, and a sibling request is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_aborts_only_the_request_it_names() {
    let mut fx = Fx::new().await;
    let slow = fx.published_item("slow.bin", &data_of(12, 60_000));
    let quick = fx.published_item("quick.bin", &data_of(13, 61_000));
    let reached = Arc::new(Notify::new());
    {
        let reached = reached.clone();
        set_hook(
            "slow.bin",
            Arc::new(move |_: &Path| {
                let reached = reached.clone();
                Box::pin(async move {
                    reached.notify_one();
                    std::future::pending::<()>().await;
                })
            }),
        );
    }
    let before = fx
        .state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(GROUP, "slow.bin")
        .unwrap();
    fx.request(b"slow", &slow, &[]);
    tokio::time::timeout(Duration::from_secs(10), reached.notified()).await.expect("assembly");
    assert_eq!(names_in(&fx.staging()).len(), 1, "the assembly should be staged");
    assert_eq!(
        fx.state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, "slow.bin")
            .unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Hydrating)
    );

    fx.request(b"quick", &quick, &[]);
    let answer = fx.response().await;
    assert_eq!(answer.request_id, b"quick".to_vec());
    assert!(answer.ok, "{}", answer.error);

    fx.cancel(b"slow");
    let cancelled = fx.response().await;
    assert_eq!(cancelled.request_id, b"slow".to_vec());
    assert_eq!(failure(&cancelled), MaterializeFailure::Cancelled);
    eventually("the cancelled request's staging file to go", || names_in(&fx.staging()).is_empty())
        .await;
    eventually("the row to revert", || {
        fx.state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, "slow.bin")
            .unwrap()
            == before
    })
    .await;
    let handed_over = fx.handoff_names();
    assert!(
        handed_over.len() == 1 && handed_over[0].starts_with(&hex::encode(b"quick")),
        "only the sibling was handed over: {handed_over:?}"
    );
    assert!(fx.repo().handoff(&fx.root, &slow).unwrap().is_none());
    // A cancel for a request that is gone changes nothing.
    fx.cancel(b"slow");
    fx.cancel(b"never-sent");
    assert!(fx.rx.try_recv().is_err());
}

/// A handoff is recorded only for a response that was actually delivered: when the connection is
/// gone, the file is removed and no ledger entry exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undelivered_response_leaves_no_handoff_and_no_ledger_entry() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("gone.bin", &data_of(14, 20_000));
    let hash = fx.current_hash(&item);
    // The connection dies before the response can be sent.
    let (dead_tx, dead_rx) = mpsc::unbounded_channel();
    drop(dead_rx);
    let message = ShellIpcMessage {
        payload: Some(Payload::MaterializeToTempRequest(MaterializeToTempRequest {
            request_id: b"req-g".to_vec(),
            root_id: hex::decode(&fx.root).unwrap(),
            item_id: item.to_vec(),
            requested_version_hash: Vec::new(),
        })),
    };
    assert!(materialize_message(&fx.context, &fx.requests, &dead_tx, &message));
    eventually("the request to finish", || fx.requests.inflight.lock().unwrap().is_empty()).await;
    assert!(fx.handoff_names().is_empty(), "an unannounced file stayed in handoff/");
    assert!(names_in(&fx.staging()).is_empty());
    assert!(fx.repo().handoff(&fx.root, &item).unwrap().is_none());
    assert_eq!(fx.current_hash(&item), hash);
    let _ = &mut fx;
}

/// A file the OS never took is removed once its lifetime has passed; one it took is left alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unconsumed_handoff_file_is_swept_after_its_lifetime() {
    let mut fx = Fx::with_lifetime(Duration::from_millis(150)).await;
    let (a, b) = (
        fx.published_item("a.bin", &data_of(15, 10_000)),
        fx.published_item("b.bin", &data_of(16, 10_000)),
    );
    let kept = fx.ask(b"keep", &a).await;
    let taken = fx.ask(b"take", &b).await;
    assert!(kept.ok && taken.ok);
    // The OS takes `take` (the path is gone) and leaves `keep` alone.
    std::fs::rename(fx.handoff_dir().join(&taken.handoff_name), fx.dir.path().join("elsewhere"))
        .unwrap();
    eventually("the unconsumed file to be swept", || fx.handoff_names().is_empty()).await;
    assert!(fx.dir.path().join("elsewhere").exists(), "a consumed file was touched");
}

/// A restart removes what a crashed run left: every staging file and the stale handoff files,
/// while a fresh handoff file (a response that just went out) is kept.
#[test]
fn a_restart_sweeps_leftovers_of_a_crashed_run() {
    let dir = tempfile::tempdir().unwrap();
    for sub in ["staging", "handoff"] {
        std::fs::create_dir_all(dir.path().join(sub)).unwrap();
    }
    std::fs::write(dir.path().join("staging/half.partial"), b"half").unwrap();
    std::fs::write(dir.path().join("staging/half.partial.tmp1"), b"half").unwrap();
    std::fs::write(dir.path().join("handoff/stale"), b"old").unwrap();
    std::thread::sleep(Duration::from_millis(400));
    std::fs::write(dir.path().join("handoff/fresh"), b"new").unwrap();

    let _root = HandoffRoot::open_with_lifetime(dir.path(), Duration::from_millis(300)).unwrap();
    assert!(names_in(&dir.path().join("staging")).is_empty());
    assert_eq!(names_in(&dir.path().join("handoff")), ["fresh"]);
}

/// A request that cannot be served says why, and builds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_that_cannot_be_served_say_why() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("x.bin", &data_of(17, 1000));

    // An unknown item.
    let response = fx.ask(b"r1", &[7; 16]).await;
    assert_eq!(failure(&response), MaterializeFailure::NotFound);
    // An unusable request id.
    fx.request(b"", &item, &[]);
    assert_eq!(failure(&fx.response().await), MaterializeFailure::NotFound);
    // A root that is not ready (the domain removed).
    let root_id = hex::decode(&fx.root).unwrap();
    send(&fx.state, domain_state(&root_id, false)).await;
    let response = fx.ask(b"r2", &item).await;
    assert_eq!(failure(&response), MaterializeFailure::NotFound, "the old root is gone");

    // No temp root configured: provider roots cannot materialize.
    let mut bare = Fx::new().await;
    let item = bare.published_item("y.bin", &data_of(18, 1000));
    bare.context = Arc::new(ShellContext::from_state(bare.state.clone()));
    let response = bare.ask(b"r3", &item).await;
    assert_eq!(failure(&response), MaterializeFailure::NotReady);

    // The disk-pressure and not-found reasons of the primitive map to their own codes.
    let pressure = SyncError::DiskPressure {
        path: "p".into(),
        volume: "v".into(),
        available_bytes: 1,
        headroom_bytes: 2,
    };
    assert_eq!(failure_of(pressure).0, MaterializeFailure::LowDisk);
    assert_eq!(failure_of(SyncError::NotFound("x".into())).0, MaterializeFailure::NotFound);
    assert_eq!(
        failure_of(SyncError::HydrationFailed("x".into())).0,
        MaterializeFailure::Unobtainable
    );
}

/// Two requests for the same item are serialized by the path and both succeed with their own file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_requests_for_one_item_each_get_their_own_file() {
    let mut fx = Fx::new().await;
    let data = data_of(19, 70_000);
    let item = fx.published_item("twice.bin", &data);
    fx.request(b"one", &item, &[]);
    fx.request(b"two", &item, &[]);
    let (first, second) = (fx.response().await, fx.response().await);
    assert!(first.ok && second.ok, "{} / {}", first.error, second.error);
    assert_ne!(first.handoff_name, second.handoff_name);
    for response in [first, second] {
        assert_eq!(std::fs::read(fx.handoff_dir().join(&response.handoff_name)).unwrap(), data);
    }
}

impl Fx {
    /// A handle over an existing state, for a hook that has to commit from inside the primitive.
    fn over(state: &Arc<DaemonState>, root: &str) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            state: state.clone(),
            root: root.to_string(),
            context: Arc::new(ShellContext::from_state(state.clone())),
            requests: MaterializeRequests::default(),
            tx,
            rx,
            dir: tempfile::tempdir().unwrap(),
        }
    }
}

#[allow(dead_code)]
fn _block(_: BlockInfo) {}

/// The empty bootstrap scaffold (`version_seq = 0`) a metadata step creates for a path it has not
/// received yet is not a version of the file: it is never handed over as a zero-byte success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bootstrap_scaffold_row_is_never_handed_over() {
    let mut fx = Fx::new().await;
    fx.commit("scaffold.bin", 0, &data_of(20, 1000));
    let item = fx.repo().mint_item(&fx.root, "scaffold.bin").unwrap();
    let response = fx.ask(b"req-s", &item).await;
    assert!(!response.ok, "a scaffold row was handed over");
    assert!(fx.handoff_names().is_empty());
    assert!(names_in(&fx.staging()).is_empty());
    assert!(fx.repo().handoff(&fx.root, &item).unwrap().is_none());
}

fn set_point(point: &'static str, key: &[u8], hook: HookFn) {
    HOOKS
        .lock()
        .unwrap()
        .get_or_insert_with(Default::default)
        .insert((point, hex::encode(key)), hook);
}

/// A version that lands between the final check and the handoff is refused BEFORE anything is
/// sent: the ledger entry cannot be written for a version that is no longer current, so no stale
/// bytes go out and nothing is recorded as handed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_committed_in_the_final_gap_is_refused_before_anything_is_sent() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("gap.bin", &data_of(21, 40_000));
    {
        let (state, root) = (fx.state.clone(), fx.root.clone());
        let fired = Arc::new(AtomicBool::new(false));
        set_point(
            "final_gap",
            &item,
            Arc::new(move || {
                let (state, root, fired) = (state.clone(), root.clone(), fired.clone());
                Box::pin(async move {
                    if !fired.swap(true, Ordering::SeqCst) {
                        let fx = Fx::over(&state, &root);
                        fx.commit("gap.bin", 2, &data_of(22, 41_000));
                    }
                })
            }),
        );
    }
    let response = fx.ask(b"req-gap", &item).await;
    assert!(!response.ok, "V1 bytes went out");
    assert_eq!(failure(&response), MaterializeFailure::VersionOutOfDate);
    assert!(fx.handoff_names().is_empty(), "a file was named in handoff/");
    assert_eq!(fx.repo().served(&fx.root, &item).unwrap(), Served::Never, "V1 counted as served");
}

/// What we MAY HAVE served is recorded BEFORE the response goes out and nothing un-records it: a
/// handoff whose framed write failed still counts (the OS may have seen the bytes).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_we_may_have_served_is_recorded_before_the_response_and_never_unrecorded() {
    let mut fx = Fx::new().await;
    let delivered = fx.published_item("ok.bin", &data_of(31, 10_000));
    let response = fx.ask(b"req-ok", &delivered).await;
    assert!(response.ok, "{}", response.error);
    assert!(matches!(fx.repo().served(&fx.root, &delivered).unwrap(), Served::Single(_)));

    let lost = fx.published_item("lost.bin", &data_of(32, 10_000));
    fx.request(b"req-lost", &lost, &[]);
    let delivery = fx.delivery().await;
    // The response is on its way: the record is already durable.
    assert!(matches!(fx.repo().served(&fx.root, &lost).unwrap(), Served::Single(_)));
    let _ = delivery.written.unwrap().send(false);
    eventually("the request to finish", || fx.requests.inflight.lock().unwrap().is_empty()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        matches!(fx.repo().served(&fx.root, &lost).unwrap(), Served::Single(_)),
        "a failed write un-recorded what we may have served"
    );
}

/// The record of what we may have served is durable BEFORE any bytes go out: when it cannot be
/// written, nothing is served, no file is named in `handoff/`, and the request fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn when_the_served_record_cannot_be_written_nothing_is_served() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("norecord.bin", &data_of(61, 12_000));
    fx.state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute_batch(
                "CREATE TRIGGER refuse_served BEFORE UPDATE OF served_content_sig ON provider_items \
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )?;
            Ok(())
        })
        .unwrap();
    let response = fx.ask(b"req-norecord", &item).await;
    assert!(!response.ok, "bytes were served without a durable record");
    assert!(fx.handoff_names().is_empty(), "a file was named in handoff/");
    assert_eq!(fx.repo().served(&fx.root, &item).unwrap(), Served::Never);
}

/// The handoff is recorded only when the socket write completed, not when the message was queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_socket_write_leaves_no_ledger_entry() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("w.bin", &data_of(23, 20_000));
    fx.request(b"req-w", &item, &[]);
    let delivery = fx.delivery().await;
    assert!(delivery.written.is_some(), "no write report asked: {:?}", delivery.message);
    // The framed write fails.
    let _ = delivery.written.unwrap().send(false);
    eventually("the request to finish", || fx.requests.inflight.lock().unwrap().is_empty()).await;
    eventually("the file to go", || fx.handoff_names().is_empty()).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        fx.repo().handoff(&fx.root, &item).unwrap().is_none(),
        "a ledger entry for an undelivered handoff"
    );
}

/// A directory fsync failure after the rename leaves nothing in `handoff/`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_sync_failure_after_the_rename_leaves_no_handoff_file() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("sync.bin", &data_of(24, 20_000));
    let root = fx.context.handoff.get().unwrap();
    root.fail_directory_sync.store(true, Ordering::SeqCst);
    let response = fx.ask(b"req-sync", &item).await;
    root.fail_directory_sync.store(false, Ordering::SeqCst);
    assert!(!response.ok);
    assert!(fx.handoff_names().is_empty(), "an untracked handoff file stayed");
    assert!(names_in(&fx.staging()).is_empty());
    assert!(fx.repo().handoff(&fx.root, &item).unwrap().is_none());
}

/// The startup sweep ages a handoff file by when it entered `handoff/`, never by the replicated
/// modification time it carries: an old mtime on a fresh file and a future mtime on a stale one
/// are both judged by the handoff time.
#[test]
fn the_startup_sweep_ignores_the_replicated_mtime() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("handoff")).unwrap();
    std::fs::create_dir_all(dir.path().join("staging")).unwrap();
    let set_mtime = |name: &str, at: std::time::SystemTime| {
        std::fs::write(dir.path().join("handoff").join(name), b"x").unwrap();
        std::fs::File::options()
            .write(true)
            .open(dir.path().join("handoff").join(name))
            .unwrap()
            .set_modified(at)
            .unwrap();
    };
    let long_ago = std::time::SystemTime::now() - Duration::from_secs(3600 * 24 * 365);
    let far_future = std::time::SystemTime::now() + Duration::from_secs(3600 * 24 * 365);
    set_mtime("fresh-old-mtime", long_ago);
    set_mtime("stale-future-mtime", far_future);
    // The second one becomes stale (by its handoff time) while the first is created later.
    std::thread::sleep(Duration::from_millis(400));
    set_mtime("fresh-old-mtime", long_ago);
    let _root = HandoffRoot::open_with_lifetime(dir.path(), Duration::from_millis(300)).unwrap();
    assert_eq!(names_in(&dir.path().join("handoff")), ["fresh-old-mtime"]);
}

/// A cancel and the completion compete for ONE terminal transition: when the cancel wins while
/// the request is finishing, the request sends nothing more and its file is removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_that_wins_the_race_is_the_only_terminal_response() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("race.bin", &data_of(25, 30_000));
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    {
        let (reached, release) = (reached.clone(), release.clone());
        set_point(
            "before_claim",
            b"race",
            Arc::new(move || {
                let (reached, release) = (reached.clone(), release.clone());
                Box::pin(async move {
                    reached.notify_one();
                    release.notified().await;
                })
            }),
        );
    }
    fx.request(b"race", &item, &[]);
    tokio::time::timeout(Duration::from_secs(10), reached.notified()).await.expect("finishing");
    assert_eq!(fx.handoff_names().len(), 1, "the file is already named in handoff/");
    fx.cancel(b"race");
    let cancelled = fx.response().await;
    assert_eq!(failure(&cancelled), MaterializeFailure::Cancelled);
    release.notify_one();
    // The finishing task lost the claim: no second response, and the named file is gone.
    eventually("the lost request's file to be removed", || fx.handoff_names().is_empty()).await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(fx.rx.try_recv().is_err(), "a second terminal response was sent");
    assert!(fx.repo().handoff(&fx.root, &item).unwrap().is_none());
}

/// A huge burst of requests is bounded twice: a connection refuses requests past its in-flight
/// limit at once, and the daemon-wide limiter lets only `ASSEMBLIES` assemblies run, however many
/// requests are waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_burst_runs_at_most_six_assemblies_and_refuses_past_the_in_flight_limit() {
    let mut fx = Fx::new().await;
    let total = MAX_INFLIGHT_REQUESTS + 10;
    let running = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut items = Vec::new();
    for n in 0..total {
        let path = format!("burst-{n:03}.bin");
        items.push(fx.published_item(&path, &data_of(40, 1000 + n)));
        let (running, peak) = (running.clone(), peak.clone());
        set_hook(
            &path,
            Arc::new(move |_: &Path| {
                let (running, peak) = (running.clone(), peak.clone());
                Box::pin(async move {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(120)).await;
                    running.fetch_sub(1, Ordering::SeqCst);
                })
            }),
        );
    }
    for (n, item) in items.iter().enumerate() {
        fx.request(format!("burst-{n}").as_bytes(), item, &[]);
    }
    let (mut ok, mut refused) = (0, 0);
    for _ in 0..total {
        let response = fx.response().await;
        if response.ok {
            ok += 1;
        } else {
            assert_eq!(failure(&response), MaterializeFailure::NotReady, "{}", response.error);
            refused += 1;
        }
    }
    assert_eq!((ok, refused), (MAX_INFLIGHT_REQUESTS, 10), "the in-flight limit did not hold");
    let peak = peak.load(Ordering::SeqCst);
    // The literal six: a test that reads the constant cannot notice the constant being raised.
    assert!(peak <= 6, "{peak} assemblies ran at once");
    assert!(peak >= 4, "the assemblies did not overlap: {peak}");
}

/// Content no peer has is a failure of that version (the Eager driver backs off); content that
/// arrives clears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unobtainable_fetch_is_recorded_and_a_successful_one_clears_it() {
    let mut fx = Fx::new().await;
    // A real row whose block is in nobody's store.
    let ghost = [9u8; 32];
    fx.state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                 version_seq, state) VALUES (?1, 'ghost.bin', 500, 1, ?2, 0, 1, 'current')",
                rusqlite::params![
                    GROUP,
                    format!(r#"[{{"hash":{:?},"offset":0,"size":500}}]"#, ghost.to_vec())
                ],
            )?;
            let row = yadorilink_sync_sqlite::read_canonical_current_row(tx, GROUP, "ghost.bin")?
                .unwrap();
            let version =
                yadorilink_replica_domain::session_state::CurrentVersionRecord::from(row.snapshot)
                    .to_file_version();
            yadorilink_sync_sqlite::dag_store::put_file_version(tx, GROUP, &version)?;
            Ok(())
        })
        .unwrap();
    let ghost_item = fx.repo().mint_item(&fx.root, "ghost.bin").unwrap();
    let response = fx.ask(b"req-ghost", &ghost_item).await;
    assert_eq!(failure(&response), MaterializeFailure::Unobtainable);
    let failure_row = fx.repo().download_failure(&fx.root, &ghost_item).unwrap().unwrap();
    assert_eq!(failure_row.failures, 1);

    let good = fx.published_item("good.bin", &data_of(41, 3000));
    let response = fx.ask(b"req-good", &good).await;
    assert!(response.ok, "{}", response.error);
    assert!(fx.repo().download_failure(&fx.root, &good).unwrap().is_none());
    // A success clears an earlier failure of the same item.
    fx.repo()
        .record_download_failure(&fx.root, &good, fx.current_hash(&good), 0, |_| 1000)
        .unwrap();
    let response = fx.ask(b"req-good-2", &good).await;
    assert!(response.ok);
    assert!(fx.repo().download_failure(&fx.root, &good).unwrap().is_none());
}

/// A request id stays reserved until the first attempt is completely done (not merely answered):
/// a retry with the same id cannot start while the first still names, or is about to clean up, a
/// handoff file of that name, and once the first is gone the retry works and its file is its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_id_is_reserved_until_the_first_attempt_is_cleaned_up() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("reuse.bin", &data_of(42, 30_000));
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    {
        let (reached, release) = (reached.clone(), release.clone());
        set_point(
            "before_claim",
            b"same",
            Arc::new(move || {
                let (reached, release) = (reached.clone(), release.clone());
                Box::pin(async move {
                    reached.notify_one();
                    release.notified().await;
                })
            }),
        );
    }
    fx.request(b"same", &item, &[]);
    tokio::time::timeout(Duration::from_secs(10), reached.notified()).await.expect("finishing");
    fx.cancel(b"same");
    assert_eq!(failure(&fx.response().await), MaterializeFailure::Cancelled);
    // The first attempt is cancelled and answered but not finished: the id is still taken.
    fx.request(b"same", &item, &[]);
    let refused = fx.response().await;
    assert!(!refused.ok, "a retry started while the first attempt still owned the id");
    release.notify_one();
    eventually("the first attempt to finish", || fx.requests.inflight.lock().unwrap().is_empty())
        .await;
    assert!(fx.handoff_names().is_empty(), "the lost attempt's file stayed");
    // Now the retry runs, and its handoff file is its own.
    HOOKS.lock().unwrap().as_mut().unwrap().remove(&("before_claim", hex::encode(b"same")));
    let retried = fx.ask(b"same", &item).await;
    assert!(retried.ok, "{}", retried.error);
    assert_eq!(fx.handoff_names(), std::slice::from_ref(&retried.handoff_name));
}

/// The exact hole: V1 is delivered (the ledger accepts it), then V2 commits and its publication
/// runs before the OS has taken the file. The publication takes the unconsumed V1 file back
/// BEFORE it evicts, so the OS cannot take V1 after V2 was published.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unconsumed_older_handoff_is_revoked_before_the_newer_version_is_published() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("race.bin", &data_of(43, 30_000));
    let v1 = fx.current_hash(&item);
    let response = fx.ask(b"req-old", &item).await;
    assert!(response.ok, "{}", response.error);
    eventually("the ledger entry", || {
        fx.repo().handoff(&fx.root, &item).unwrap().is_some_and(|h| h.version_hash == v1)
    })
    .await;
    assert_eq!(fx.handoff_names().len(), 1, "V1's file is still unconsumed");

    // V2 commits; a host answers the publication's eviction (nothing to evict: the OS has not
    // taken V1) and its signal.
    fx.commit("race.bin", 2, &data_of(44, 31_000));
    let (host, mut host_rx) = mpsc::unbounded_channel::<ShellIpcMessage>();
    assert!(fx.context.provider_host.try_attach(host));
    let answering = fx.context.clone();
    let responder = tokio::spawn(async move {
        while let Some(message) = host_rx.recv().await {
            match message.payload {
                Some(Payload::ProviderEvictRequest(request)) => {
                    answering.provider_host.complete_evict(
                        &yadorilink_ipc_proto::shellipc::ProviderEvictDone {
                            root_id: request.root_id,
                            request_id: request.request_id,
                            result: yadorilink_ipc_proto::shellipc::EvictResult::NotMaterialized
                                as i32,
                            error: String::new(),
                        },
                    );
                }
                Some(Payload::ProviderChanged(changed)) => {
                    answering.provider_host.complete_signal(
                        &yadorilink_ipc_proto::shellipc::ProviderSignalDone {
                            root_id: changed.root_id,
                            namespace_revision: changed.namespace_revision,
                            ok: true,
                            error: String::new(),
                            request_id: changed.request_id,
                        },
                    );
                }
                _ => {}
            }
        }
    });
    fx.context.publication.kick(&fx.root);
    // V2 is announced (published only later, by a confirmed handoff or the timer): the old file
    // was taken back BEFORE the announcement.
    eventually("V2 to be announced", || fx.repo().announced_is_current(&fx.root, &item).unwrap())
        .await;
    assert!(
        fx.handoff_names().is_empty(),
        "V1's file survived V2's publication: the OS could still take it"
    );
    responder.abort();
}

/// The bytes come back with the 40-byte token they are paired with: the version hash and the
/// item generation read in the transaction that recorded the handoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_response_pairs_the_bytes_with_the_hash_and_generation_of_the_handoff() {
    let mut fx = Fx::new().await;
    let item = fx.published_item("tok.bin", &data_of(71, 9_000));
    let response = fx.ask(b"req-tok", &item).await;
    assert!(response.ok, "{}", response.error);
    assert_eq!(response.content_version.len(), 40);
    assert_eq!(response.content_version[..32], response.version_hash[..]);
    let generation: i64 = fx
        .state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT generation FROM provider_items WHERE item_id = ?1",
                [&item[..]],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(response.content_version[32..], (generation as u64).to_be_bytes());
}
