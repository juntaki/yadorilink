use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_ipc_proto::sync as proto;
use yadorilink_local_storage::BlockStore;
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_peer_session::rate_limiter::RateLimiters;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

// One block exchange is one bidirectional stream, so the response's outcome
// oneof is the type these tests match on constantly. Aliased because the
// generated path (`proto::block_response_header::Outcome`) is long enough to
// push every assertion that names it onto its own line.
use proto::block_response_header::Outcome as BlockOutcome;

// Every fixture these tests are built on -- `Device`, the session spawners,
// `checkpointed_batch`, the raw block-request helpers -- lives in
// `yadorilink-daemon`, next to the `ReplicaCoordinator` it is built on, and
// is reached here through this crate's existing dev-dependency on it.
use yadorilink_daemon::test_support::peer_session_fixture::*;

/// An eager file whose bytes go missing under a row that still names the same
/// version must be restored by the repair audit, not left as a hole.
///
/// This is the interrupted-materialization shape, not a user deleting a file:
/// the row says `Placeholder` for a version this device already holds, and
/// nothing else will ever re-drive it. The audit is the only thing that
/// notices.
///
/// Stated with the content in this device's own store. Where the bytes come
/// from is the block lane's business and has its own tests; what is under test
/// here is that the audit re-drives materialization at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn same_version_resync_rehydrates_a_missing_eager_file() {
    let device_b = Device::new("device-b").await;
    let root_b = device_b.root_path().to_string_lossy().to_string();
    link_with_completed_startup(&device_b.state, &root_b);

    let file_name = "stuck.bin";
    let contents = vec![0x5Au8; 300_000];
    device_b.producer().commit_create(GROUP, file_name, &contents, 0);
    let session_b = spawn_session(&device_b, "device-a");

    let replicated_path = device_b.root_path().join(file_name);
    let _ = std::fs::remove_file(&replicated_path);
    device_b
        .state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            file_name,
            MaterializationState::Placeholder,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    // Drive the audit until the row reaches its terminal state, not until
    // the bytes land. Rehydration writes the file first and commits the
    // `Hydrating -> Hydrated` transition last: `reconstruct_file` (fsync,
    // rename, parent-dir fsync), then the materialized-fingerprint write,
    // then `apply_unix_mode`, and only then
    // `transition_materialization_state_if_same_authoring`. Breaking out
    // of this loop on the disk bytes and then asserting the state column
    // was reading the two ends of that window in the wrong order.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        drive_materialization_for_test(&session_b, &device_b.state, GROUP).await.unwrap();
        if device_b
            .state
            .materialization_state_repository()
            .get_materialization_state(GROUP, file_name)
            .unwrap()
            == Some(MaterializationState::Hydrated)
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "repair audit never rehydrated the file");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert_eq!(std::fs::read(&replicated_path).unwrap(), contents);
}

/// An existing link's root is the user's folder: it was created when the link
/// was made, so finding it missing when a session starts means something is
/// wrong — most often an external volume whose mountpoint is gone — not that
/// setup is owed. Creating it would rebuild the user's folder as an empty
/// directory on the internal disk, which makes a broken link look healthy, hides
/// the real fault, and lets peer content start filling the boot volume in place
/// of the detached one.
#[tokio::test]
async fn session_construction_never_creates_a_missing_sync_root() {
    let device_b = Device::new("device-b").await;

    // The shape of an external volume that is not mounted: the link row still
    // names a path, and nothing is there. Re-point the fixture's link at that
    // path rather than adding a second one, so the group has exactly one row.
    let missing_root = device_b.root_path().join("not-mounted");
    device_b.state.link_repository().remove_link(&device_b.root_path().to_string_lossy()).unwrap();
    device_b.state.link_repository().add_link(&missing_root.to_string_lossy(), GROUP).unwrap();
    assert!(!missing_root.exists(), "precondition: the root must start absent");

    let peer_transports = device_b.node.transports_for("device-a");
    let replica_engine =
        yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
            &device_b.state,
            device_b.store.clone(),
        );
    let _session = PeerSyncSession::over_substrate(
        device_b.device_id.clone(),
        "device-a".to_string(),
        device_b.state.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        device_b.store.clone(),
        vec![GROUP.to_string()],
        HashMap::from([(GROUP.to_string(), missing_root.clone())]),
        yadorilink_peer_session::ports::SessionTransports {
            blocks: peer_transports.clone(),
            service: peer_transports.clone(),
            prepared_snapshots: device_b.prepared_snapshots.clone(),
            snapshot_fetch: peer_transports,
        },
        None,
        yadorilink_peer_session::peer_session::PeerSyncSessionDeps::test_permissive(),
    );

    assert!(
        !missing_root.exists(),
        "session construction recreated an existing link's root on the internal disk; a missing \
         root must surface as a fault, not be silently rebuilt"
    );
}

/// Security regression test: a session must ignore index/block messages
/// for a folder group it wasn't constructed with (the ACL-verified
/// intersection from the coordination plane), even if a peer sends them —
/// a peer naming an unrelated group_id in a message must not be able to
/// read or write files outside what it's actually authorized to share.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unauthorized_group_id_in_incoming_message_is_ignored() {
    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;

    let file_path = device_a.root_path().join("private.txt");
    std::fs::write(&file_path, b"not for device-b").unwrap();
    device_a
        .processor()
        .process_event(
            GROUP,
            &device_a.root_path(),
            &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap();

    // A still thinks it shares GROUP with B (e.g. a stale/incorrect local
    // assumption); B's session was constructed with an *empty* shared-group
    // list, simulating "the coordination plane's ACL does not actually
    // authorize this pairing for GROUP."
    let _session_a = spawn_session_with_groups(&device_a, "device-b", vec![GROUP.to_string()]);
    let _session_b = spawn_session_with_groups(&device_b, "device-a", vec![]);

    // Give plenty of time for A's full index send to arrive and (if the
    // guard were missing) be materialized.
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(
        !device_b.root_path().join("private.txt").exists(),
        "file for an unauthorized group must never be written to disk"
    );
    assert!(device_b
        .state
        .file_index_repository()
        .get_file(GROUP, "private.txt")
        .unwrap()
        .is_none());
}

/// Security regression test: unlike every other group-scoped inbound
/// handler in this file (`handle_change_request`, `handle_change_batch`,
/// `handle_heads_announce`, `handle_block_request`, the handoff/rebootstrap
/// handlers), `handle_version_present_query` used to skip the
/// `shares_group` re-check entirely and answer straight from
/// `holds_version_durably` -- which performs no caller authorization of
/// its own. A peer no longer (or never) authorized for a group could
/// therefore learn, from a truthful `present`/absent ack, whether specific
/// content is durably held there. This drives the real wire path (a live
/// `request_version_present` call against a live, connected peer session),
/// not a bare predicate call, and uses the SAME durable-version setup for
/// both an unauthorized and an authorized responder so the `false` result
/// is provably caused by the missing authorization check, not by some
/// unrelated setup mistake making the version look absent either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn version_present_query_for_an_unauthorized_group_is_refused_not_answered_truthfully() {
    use yadorilink_replica_domain::file::VersionBlock;
    use yadorilink_replica_domain::ids::BlockHash;

    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;

    // Device B durably holds this exact version, group provenance
    // included -- the precondition `holds_version_durably` requires before
    // it will ever answer `present: true` for anyone.
    let content = b"device-b's own durably held content";
    let hash_hex = device_b.store.put(content).unwrap();
    let hash_bytes = hex::decode(hash_hex.as_str()).unwrap();
    let record = yadorilink_replica_domain::file::FileRecord {
        path: "a.bin".to_string(),
        size: content.len() as u64,
        mtime_unix_nanos: 1,
        blocks: vec![yadorilink_replica_domain::file::BlockInfo {
            hash: hash_bytes.clone(),
            offset: 0,
            size: content.len() as u32,
        }],
        deleted: false,
    };
    device_b
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let retained = device_b.state.sqlite().dag_list_versions(GROUP, "a.bin").unwrap();
    assert_eq!(retained.len(), 1, "sanity: the single upsert retains exactly one version");
    let version_hash = yadorilink_replica_domain::ids::VersionHash(retained[0].version_hash.0);
    device_b
        .state
        .change_history_repository()
        .record_group_block_provenance(GROUP, std::slice::from_ref(&hash_bytes))
        .unwrap();
    let blocks = vec![VersionBlock { hash: BlockHash(hash_bytes), size: content.len() as u32 }];

    // Authorized control FIRST, same durable-version setup: proves the
    // `false` in the unauthorized scenario below is caused by the
    // authorization gate, not by the version somehow looking absent
    // regardless of who asks.
    {
        let session_a = spawn_session_with_groups(&device_a, "device-b", vec![GROUP.to_string()]);
        let _session_b = spawn_session_with_groups(&device_b, "device-a", vec![GROUP.to_string()]);

        let present = session_a
            .session
            .request_version_present(GROUP, "a.bin", version_hash, &blocks, true)
            .await;
        assert!(
            present,
            "sanity: an authorized peer querying the identical durably-held version must get \
             present:true -- otherwise the false below wouldn't be proving what this test claims"
        );
    }

    // Unauthorized: B's own session was constructed with an *empty*
    // shared-group list for GROUP, simulating "the coordination plane's
    // ACL does not actually authorize this pairing" -- the exact scenario
    // `unauthorized_group_id_in_incoming_message_is_ignored` above uses for
    // every other message type.
    {
        let session_a = spawn_session_with_groups(&device_a, "device-b", vec![GROUP.to_string()]);
        let _session_b = spawn_session_with_groups(&device_b, "device-a", vec![]);

        let present = session_a
            .session
            .request_version_present(GROUP, "a.bin", version_hash, &blocks, true)
            .await;
        assert!(
            !present,
            "an unauthorized/unshared peer must never receive a truthful present:true for \
             content it has no authorization to even ask about"
        );
    }
}

/// Two concurrent requests for the identical block hash, in two different
/// folder groups, must not be cross-wired: each gets its own peer's answer
/// for its own group, even when those answers disagree.
///
/// Nothing correlates a request to its answer any more except the stream
/// they share, so this is the property that replaces the old
/// `request_id`-uniqueness defence -- and it is a stronger one, because two
/// exchanges on two streams were never on the same channel to begin with,
/// where two ids merely had to differ.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_requests_for_one_hash_in_two_groups_are_not_cross_wired() {
    const OTHER_GROUP: &str = "shared-documents";
    let device_b = Device::new("device-b").await;
    let data = b"one block, referenced from two different groups".to_vec();
    let hash = sha256_bytes(&data);

    // The peer this test plays itself, as a real substrate endpoint in
    // device_b's world -- see `Device::fake_peer`.
    let responder_node = device_b.fake_peer("device-a").await;
    let session_b = spawn_session_without_convergence_driver(&device_b, "device-a");
    let responder_data = data.clone();
    let responder_node_for_task = responder_node.clone();
    let responder = tokio::spawn(async move {
        // Answers on the request's own group, never on arrival order: the
        // two requests genuinely race, so a responder that assumed an order
        // would be testing its own sequencing rather than the requester's
        // ability to keep two answers apart.
        serve_block_requests_on_lane(&responder_node_for_task, 2, |_, request| {
            if request.folder_group_id == GROUP {
                BlockAnswer::found(responder_data.clone())
            } else {
                BlockAnswer::DontHave
            }
        })
        .await;
    });

    let (served, refused) = tokio::join!(
        session_b.session.fetch_block(GROUP, "shared.bin", &hash),
        session_b.session.fetch_block(OTHER_GROUP, "shared.bin", &hash),
    );
    await_responder(responder).await;

    assert_eq!(
        served.unwrap().map(|bytes| bytes.to_vec()),
        Some(data),
        "the group the peer served must receive the block"
    );
    assert!(
        refused.unwrap().is_none(),
        "the group the peer refused must receive nothing -- an identical hash in another group \
         is a different question, and its answer must not be handed to this one"
    );
}

/// A `Busy` answer is a "come back later, with a hint how much later", not
/// a "no": the requester must retry the same peer and must wait out the
/// hint before it does.
#[tokio::test]
async fn requester_honors_busy_retry_after_before_retrying_same_peer() {
    let device_b = Device::new("device-b").await;
    let data = b"available after one busy response".to_vec();
    let hash = sha256_bytes(&data);

    // The peer this test plays itself, as a real substrate endpoint in
    // device_b's world -- see `Device::fake_peer`.
    let responder_node = device_b.fake_peer("device-a").await;
    let session_b = spawn_session_without_convergence_driver(&device_b, "device-a");
    let responder_node_for_task = responder_node.clone();
    let responder = tokio::spawn(async move {
        // Timed from the responder's side rather than the requester's: what
        // is being measured is the gap between the two requests actually
        // arriving, which is the only thing the peer's `retry_after_ms`
        // hint can influence.
        let mut first_request_at = None;
        serve_block_requests_on_lane(&responder_node_for_task, 2, |index, _| {
            if index == 0 {
                first_request_at = Some(tokio::time::Instant::now());
                BlockAnswer::Busy { retry_after_ms: 80, queue_depth: 1 }
            } else {
                BlockAnswer::found(data.clone())
            }
        })
        .await;
        first_request_at.expect("the first request must have been served").elapsed()
    });

    let received = session_b
        .session
        .fetch_block(GROUP, "busy.bin", &hash)
        .await
        .unwrap()
        .expect("the retry must receive the block");
    let retry_delay = responder.await.unwrap();

    assert_eq!(&received[..], b"available after one busy response");
    assert!(
        retry_delay >= Duration::from_millis(70),
        "retry ignored the peer's 80ms backoff hint: {retry_delay:?}"
    );
}

/// group authorization alone is not enough to serve arbitrary
/// block-store contents. The requested hash must be referenced by the
/// requested file record in that group.
#[tokio::test]
async fn block_request_for_unreferenced_hash_is_refused() {
    let device_a = Device::new("device-a").await;

    let public_data = b"public file contents".to_vec();
    let public_hash = sha256_bytes(&public_data);
    let secret_data = b"secret orphan block".to_vec();
    let secret_hash = sha256_bytes(&secret_data);
    device_a.store.put(&public_data).unwrap();
    device_a.store.put(&secret_data).unwrap();

    device_a
        .state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "public.bin".into(),
                size: public_data.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: public_hash,
                    offset: 0,
                    size: public_data.len() as u32,
                }],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    let requester = device_a.fake_peer("device-b").await;
    let _session_a = spawn_session(&device_a, "device-b");

    let (response, body) = request_block(&requester, "device-a", "public.bin", &secret_hash).await;

    assert!(
        matches!(response.outcome, Some(BlockOutcome::DontHave(true))),
        "unreferenced block hash must be refused, got {:?}",
        response.outcome
    );
    assert!(body.is_empty(), "a refused request must carry no block bytes at all");
}

/// "A mid-session revocation stops further block requests without
/// waiting for teardown": a block request that was valid when the
/// session started must be refused once a netmap update
/// revokes that group edge mid-session — even though nothing here tears
/// down the transport-level `QuicPeerChannel`/connection (that reaction is
/// a separate concern, deliberately exercised nowhere in this test).
/// `PeerSyncSession::revoke_group` is the hook a daemon-level netmap-diff
/// reaction is expected to call; this test calls it directly to simulate
/// that reaction landing mid-session, proving the sync-engine layer's own
/// defense works independently of whether transport teardown has happened
/// yet.
#[tokio::test]
async fn block_request_is_refused_after_mid_session_group_revocation() {
    let device_a = Device::new("device-a").await;

    let data = b"public file contents, initially authorized".to_vec();
    let hash = sha256_bytes(&data);
    // `commit_create` + `publish_pending` (not a raw `store.put` +
    // `upsert_file`): block-serving authorization requires a real
    // PUBLISHED Change backing the served path -- see `PeerReplicaSession::block_request_is_
    // referenced`'s own doc comment.
    device_a.producer().commit_create(GROUP, "public.bin", &data, 0);
    device_a.publish_pending();

    let requester = device_a.fake_peer("device-b").await;
    // session_a is the *answering* side — its live authorization is what
    // gets revoked mid-session below.
    let session_a = spawn_session(&device_a, "device-b");
    assert!(
        session_a.session.shares_group(GROUP),
        "sanity: session starts out authorized for GROUP"
    );

    // Baseline: while still authorized, the request succeeds.
    let (first_response, first_body) =
        request_block(&requester, "device-a", "public.bin", &hash).await;
    let found = expect_found(&first_response);
    assert_eq!(found.hash, hash, "a Found response must echo the hash it answers");
    assert_eq!(first_body, data);

    // Simulate a netmap update revoking device-b's authorization for GROUP
    // as seen by device-a's session, mid-session — nothing here touches
    // `requester`'s own substrate link, so the transport-level tunnel stays
    // fully connected and open throughout.
    session_a.session.revoke_group(GROUP);
    assert!(
        !session_a.session.shares_group(GROUP),
        "revoke_group must be reflected immediately, without waiting for anything else"
    );

    // Same request, same still-open connection, now refused.
    let (second_response, second_body) =
        request_block(&requester, "device-a", "public.bin", &hash).await;
    assert!(
        matches!(second_response.outcome, Some(BlockOutcome::Rejected(_))),
        "block request must be refused once a mid-session revocation is reflected in local \
         netmap/ACL state, even though the transport connection hasn't been torn down -- got \
         {:?}",
        second_response.outcome
    );
    assert!(second_body.is_empty(), "a refused request must carry no block bytes at all");
}

/// Regression for a confirmed disclosure window: `handle_block_request`
/// checks `shares_group` once, then `handle_block_request_with_credit`
/// can wait up to `DISPATCH_WAIT_BUDGET` (~2s) for a fair dispatch turn
/// before ever reading or sending the block. If authorization is revoked
/// WHILE a request is merely waiting its turn, the (fixed) code must
/// re-check before proceeding -- otherwise a just-revoked peer would
/// still receive content for however long its request happened to be
/// queued. Forces the exact race deterministically: this test itself
/// holds `device-b`/`GROUP`'s one dispatch slot (via the same public
/// `acquire_dispatch_turn` the real session calls), so the real
/// block request sent below is GUARANTEED to be queued, not granted
/// immediately -- revocation happens while it waits, and only then does
/// this test release the slot to let it proceed.
#[tokio::test]
async fn block_request_is_rejected_if_authorization_is_revoked_while_waiting_for_a_dispatch_turn() {
    let device_a = Device::new("device-a").await;

    let data = b"content revoked mid-dispatch-wait".to_vec();
    let hash = sha256_bytes(&data);
    device_a.producer().commit_create(GROUP, "dispatch-wait.bin", &data, 0);
    device_a.publish_pending();

    let requester = device_a.fake_peer("device-b").await;
    let session_a = spawn_session(&device_a, "device-b");
    let engine = yadorilink_peer_session::block_serve::BlockServeEngine::new(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        1,
    );
    session_a.session.set_block_serve_engine(engine.clone());
    assert!(
        session_a.session.shares_group(GROUP),
        "sanity: session starts out authorized for GROUP"
    );

    // Occupy the one dispatch slot for exactly the key ("device-b", GROUP)
    // the real request below will need, so it is guaranteed to queue.
    let holder_guard = engine.acquire_dispatch_turn("device-b", GROUP, 1).await.unwrap();

    // Left in flight deliberately: the request's own stream stays open with
    // nothing read off it yet, which is exactly the state the serving side
    // is in while it waits for a dispatch turn.
    let mut request = begin_block_request(&requester, "device-a", "dispatch-wait.bin", &hash).await;
    // Give the serving side a moment to accept the stream, spawn its
    // handler and reach (and block on) `acquire_dispatch_turn`.
    tokio::time::sleep(Duration::from_millis(200)).await;

    session_a.session.revoke_group(GROUP);
    assert!(!session_a.session.shares_group(GROUP));

    // Release the slot now -- the queued request is granted its turn only
    // AFTER the revocation above.
    drop(holder_guard);

    let (response, _body) =
        tokio::time::timeout(Duration::from_secs(3), read_block_response(&mut request))
            .await
            .expect("the request must resolve promptly once its dispatch turn is granted");
    assert!(
        matches!(response.outcome, Some(BlockOutcome::Rejected(_))),
        "a peer whose authorization was revoked WHILE its request merely waited for a dispatch \
         turn must be refused, not served -- got {:?}",
        response.outcome
    );
}

/// An authorized peer is served the content it requests:
/// block reads are gated only on group authorization (`shares_group`), and
/// every authorized device is a full bidirectional peer, so a peer sharing
/// the group is served existing content normally. Mirrors
/// `block_request_is_refused_after_mid_session_group_revocation`'s structure,
/// but here authorization stays in place, so the request must NOT be refused.
#[tokio::test]
async fn block_requests_are_served_to_an_authorized_peer() {
    let device_a = Device::new("device-a").await;

    let data = b"authorized peers may read this content".to_vec();
    let hash = sha256_bytes(&data);
    // See `block_request_is_refused_after_mid_session_group_revocation`
    // above for why this is `commit_create` + `publish_pending`, not a raw
    // `store.put` + `upsert_file`.
    device_a.producer().commit_create(GROUP, "readable.bin", &data, 0);
    device_a.publish_pending();

    let requester = device_a.fake_peer("device-b").await;
    // session_a is the *answering* side, playing the sharer who has
    // authorized device-b for GROUP.
    let session_a = spawn_session(&device_a, "device-b");
    assert!(session_a.session.shares_group(GROUP), "sanity: the peer is authorized for the group");

    let (response, body) = request_block(&requester, "device-a", "readable.bin", &hash).await;
    let Some(BlockOutcome::Found(found)) = &response.outcome else {
        panic!(
            "an authorized peer must be served existing content: block requests are gated only \
             on group authorization (shares_group) -- got {:?}",
            response.outcome
        );
    };
    assert_eq!(found.hash, hash, "a Found response must echo the hash it answers");
    assert_eq!(body, data);
}

/// Pins invariant 1 (`shares_group` rejection path) from the peer-handler
/// inventory doc's deep dive: `examination_permits` must be dropped (the
/// doc's line ~5710) strictly before the non-blocking `Rejected` reply that
/// path sends. Proven by leaving the device exactly one free examination
/// slot, sending an unauthorized request down this exact path, waiting for
/// its reply, then sending a second request that can only avoid a `Busy`
/// reply of its own if the first request's slot was already back.
#[tokio::test]
async fn examination_permit_is_released_before_reply_on_shares_group_rejection() {
    let device_a = Device::new("device-a").await;

    let requester = device_a.fake_peer("device-b").await;
    // No shared groups at all -- every request fails `shares_group`,
    // regardless of file path or hash, before either is ever looked up.
    let session_a = spawn_session_with_groups(&device_a, "device-b", vec![]);
    let (engine, held_permits) = engine_with_one_free_examination_slot();
    session_a.session.set_block_serve_engine(engine);

    let hash_1 = sha256_bytes(b"first unauthorized request");
    let (response_1, _) = request_block(&requester, "device-a", "whatever-1.bin", &hash_1).await;
    assert!(
        matches!(response_1.outcome, Some(BlockOutcome::Rejected(_))),
        "sanity: this path must be the shares_group rejection, got {:?}",
        response_1.outcome
    );

    let hash_2 = sha256_bytes(b"second unauthorized request, the probe");
    let (response_2, _) = request_block(&requester, "device-a", "whatever-2.bin", &hash_2).await;
    assert!(
        !matches!(response_2.outcome, Some(BlockOutcome::Busy(_))),
        "the probe request must not be denied examination admission by the accept loop's own \
         try_begin_examination gate -- the only spare examination slot this device had must \
         already have been returned by the first request's own reply time, got {:?}",
        response_2.outcome
    );
    assert!(
        matches!(response_2.outcome, Some(BlockOutcome::Rejected(_))),
        "sanity: the probe must take the identical shares_group rejection path, got {:?}",
        response_2.outcome
    );
    drop(held_permits);
}

/// Pins invariant 1 (`block_request_is_referenced` rejection path): the
/// doc's line ~5732.
#[tokio::test]
async fn examination_permit_is_released_before_reply_when_block_is_not_referenced() {
    let device_a = Device::new("device-a").await;

    let requester = device_a.fake_peer("device-b").await;
    let session_a = spawn_session(&device_a, "device-b");
    let (engine, held_permits) = engine_with_one_free_examination_slot();
    session_a.session.set_block_serve_engine(engine);

    // Neither hash is referenced by any file record, in the DAG, or as a
    // retained version -- `block_request_is_referenced` returns false for
    // both, with nothing seeded in device-a's state at all.
    let hash_1 = sha256_bytes(b"first unreferenced hash");
    let (response_1, _) =
        request_block(&requester, "device-a", "unreferenced-1.bin", &hash_1).await;
    assert!(
        matches!(response_1.outcome, Some(BlockOutcome::DontHave(true))),
        "sanity: this path must be the not-referenced dont_have path, got {:?}",
        response_1.outcome
    );

    let hash_2 = sha256_bytes(b"second unreferenced hash, the probe");
    let (response_2, _) =
        request_block(&requester, "device-a", "unreferenced-2.bin", &hash_2).await;
    assert!(
        !matches!(response_2.outcome, Some(BlockOutcome::Busy(_))),
        "the probe request must not be denied examination admission -- the only spare \
         examination slot must already have been returned by the first request's own reply \
         time, got {:?}",
        response_2.outcome
    );
    assert!(
        matches!(response_2.outcome, Some(BlockOutcome::DontHave(true))),
        "sanity: the probe must take the identical not-referenced path, got {:?}",
        response_2.outcome
    );
    drop(held_permits);
}

/// Pins invariant 1 (`group_has_block_provenance` rejection path): the
/// doc's line ~5745.
#[tokio::test]
async fn examination_permit_is_released_before_reply_when_group_has_no_block_provenance() {
    let device_a = Device::new("device-a").await;
    let hash_1 = seed_referenced_block_without_provenance(
        &device_a,
        "no-provenance-1.bin",
        b"referenced but never obtained through this group",
    );
    let hash_2 = seed_referenced_block_without_provenance(
        &device_a,
        "no-provenance-2.bin",
        b"same story, the probe",
    );

    let requester = device_a.fake_peer("device-b").await;
    let session_a = spawn_session(&device_a, "device-b");
    let (engine, held_permits) = engine_with_one_free_examination_slot();
    session_a.session.set_block_serve_engine(engine);

    let (response_1, _) =
        request_block(&requester, "device-a", "no-provenance-1.bin", &hash_1).await;
    assert!(
        matches!(response_1.outcome, Some(BlockOutcome::Rejected(_))),
        "sanity: this path must be the no-provenance rejection, got {:?}",
        response_1.outcome
    );

    let (response_2, _) =
        request_block(&requester, "device-a", "no-provenance-2.bin", &hash_2).await;
    assert!(
        !matches!(response_2.outcome, Some(BlockOutcome::Busy(_))),
        "the probe request must not be denied examination admission -- the only spare \
         examination slot must already have been returned by the first request's own reply \
         time, got {:?}",
        response_2.outcome
    );
    assert!(
        matches!(response_2.outcome, Some(BlockOutcome::Rejected(_))),
        "sanity: the probe must take the identical no-provenance rejection path, got {:?}",
        response_2.outcome
    );
    drop(held_permits);
}

/// Pins invariant 1 (the pass-through/serve path): the doc's line ~5778,
/// where the drop is unconditional and happens BEFORE dispatch even
/// begins -- so it must already be back well before the first request's
/// own (much later) `Found` reply.
#[tokio::test]
async fn examination_permit_is_released_before_reply_on_the_pass_through_serve_path() {
    let device_a = Device::new("device-a").await;
    let data_1 = b"first fully servable block".to_vec();
    let hash_1 = seed_referenced_block(&device_a, "servable-1.bin", &data_1);
    let data_2 = b"second fully servable block, the probe".to_vec();
    let hash_2 = seed_referenced_block(&device_a, "servable-2.bin", &data_2);

    let requester = device_a.fake_peer("device-b").await;
    let session_a = spawn_session(&device_a, "device-b");
    let (engine, held_permits) = engine_with_one_free_examination_slot();
    session_a.session.set_block_serve_engine(engine);

    let (response_1, body_1) =
        request_block(&requester, "device-a", "servable-1.bin", &hash_1).await;
    if !matches!(response_1.outcome, Some(BlockOutcome::Found(_))) {
        panic!(
            "sanity: this path must be the pass-through serve path, got {:?}",
            response_1.outcome
        );
    }
    assert_eq!(body_1, data_1);

    let (response_2, body_2) =
        request_block(&requester, "device-a", "servable-2.bin", &hash_2).await;
    assert!(
        !matches!(response_2.outcome, Some(BlockOutcome::Busy(_))),
        "the probe request must not be denied examination admission -- on this path \
         examination_permits is dropped unconditionally before dispatch even begins, so it \
         must already have been returned well before the first request's own reply, got {:?}",
        response_2.outcome
    );
    if !matches!(response_2.outcome, Some(BlockOutcome::Found(_))) {
        panic!("sanity: the probe must also be served, got {:?}", response_2.outcome);
    }
    assert_eq!(body_2, data_2);
    drop(held_permits);
}

/// Pins invariant 2 from the peer-handler inventory doc's deep dive: a
/// block request that cannot get a fair dispatch turn within
/// `DISPATCH_WAIT_BUDGET` (~2s, `handle_block_request_with_credit`'s own
/// constant) must give up and answer `Busy` rather than hang past that
/// budget. A precise millisecond assertion would be fragile against
/// scheduler jitter; this instead asserts a bounded window loose enough to
/// tolerate ordinary jitter but tight enough that it would fail outright if
/// `DISPATCH_WAIT_BUDGET` were, say, 10x too large (20s instead of 2s).
///
/// Forces the wait deterministically the same way
/// `block_request_is_rejected_if_authorization_is_revoked_while_waiting_
/// for_a_dispatch_turn` above does: this test itself holds the one
/// dispatch slot for `("device-b", GROUP)` via the same public
/// `acquire_dispatch_turn` the real session calls -- but here, unlike that
/// test, the slot is never released, so the real request's own wait is
/// guaranteed to run out the clock instead of being granted a turn.
#[tokio::test]
async fn dispatch_wait_budget_timeout_returns_busy_within_a_bounded_window() {
    let device_a = Device::new("device-a").await;
    let hash = seed_referenced_block(
        &device_a,
        "dispatch-timeout.bin",
        b"content stuck behind a permanently busy dispatch slot",
    );

    let requester = device_a.fake_peer("device-b").await;
    let session_a = spawn_session(&device_a, "device-b");
    let engine = yadorilink_peer_session::block_serve::BlockServeEngine::new(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        1,
    );
    session_a.session.set_block_serve_engine(engine.clone());

    // Occupy the one dispatch slot for this exact key and never release it.
    let _never_released_dispatch_guard =
        engine.acquire_dispatch_turn("device-b", GROUP, 1).await.unwrap();

    let started = Instant::now();
    let mut request =
        begin_block_request(&requester, "device-a", "dispatch-timeout.bin", &hash).await;

    let (response, _body) =
        tokio::time::timeout(Duration::from_secs(6), read_block_response(&mut request))
            .await
            .expect(
                "the request must resolve, not hang forever, once DISPATCH_WAIT_BUDGET elapses",
            );
    let elapsed = started.elapsed();

    assert!(
        matches!(response.outcome, Some(BlockOutcome::Busy(_))),
        "a request that can never get a dispatch turn must answer Busy once its wait budget \
         elapses, got {:?}",
        response.outcome
    );
    assert!(
        elapsed < Duration::from_secs(4),
        "the Busy reply took {elapsed:?} -- DISPATCH_WAIT_BUDGET is documented as 2s, so this \
         bound (2x that) would fail if a future change grew it by even a modest multiple (it \
         must stay well under FETCH_RESPONSE_TIMEOUT's own 5s deadline, per that constant's own \
         doc comment)"
    );
    assert!(
        elapsed >= Duration::from_millis(1_500),
        "the Busy reply arrived suspiciously fast ({elapsed:?}) for a wait that should run out \
         essentially the entire ~2s DISPATCH_WAIT_BUDGET -- this would fail if the timeout were \
         accidentally applied to the wrong wait, or bypassed entirely"
    );
}

/// Pins invariant 3 from the peer-handler inventory doc's deep dive, the
/// highest-value invariant in this family: `credit_guard` (`ServeCreditGuard`)
/// must be dropped only AFTER the block response send actually completes, not
/// before -- see `handle_block_request_with_credit`'s own comment mirroring
/// the "72 concurrent requests" incident this exact ordering exists to
/// prevent a repeat of. A byte-budget window where credit looks free while
/// the bytes are still in flight on the wire would let a burst of new
/// requests over-admit against a budget that hasn't actually been vacated.
///
/// Forces the ordering deterministically by throttling the SERVING side's
/// own upload rate limiter (`PeerSyncSession::set_rate_limiters`, the same
/// public, production seam a daemon uses to enforce a configured transfer
/// cap) down to a rate that turns one block's `upload.acquire` call --
/// which runs strictly BEFORE the reply send and, transitively, strictly
/// before `credit_guard`'s drop -- into a multi-second, deterministic delay
/// window. A second, identically-sized block from the same peer/group is
/// requested mid-window, when the FIRST request's credit reservation
/// (sized to consume the entire per-peer/per-group/global budget on its
/// own) must still be held if the documented ordering holds -- and is
/// asserted `Busy` because of it. A third request, issued only after the
/// first's `Found` reply has actually been observed, is then asserted to
/// succeed, proving the credit was released once that reply completed, not
/// held forever (and not released any earlier either).
#[tokio::test]
async fn credit_guard_is_released_only_after_the_reply_finishes_sending() {
    let device_a = Device::new("device-a").await;

    // Incompressible on purpose. The whole mechanism this test relies on is
    // the serving side's upload rate limiter turning one block into a
    // multi-second send, and that limiter debits the bytes that actually go
    // on the wire -- which, for a block the responder can compress, is a
    // tiny fraction of `BLOCK_LEN` and no window at all.
    const BLOCK_LEN: usize = 6_000;
    let block_a = seed_referenced_block(
        &device_a,
        "credit-a.bin",
        &incompressible_bytes("credit-a", BLOCK_LEN),
    );
    let block_b = seed_referenced_block(
        &device_a,
        "credit-b.bin",
        &incompressible_bytes("credit-b", BLOCK_LEN),
    );
    let block_c = seed_referenced_block(
        &device_a,
        "credit-c.bin",
        &incompressible_bytes("credit-c", BLOCK_LEN),
    );

    let requester = device_a.fake_peer("device-b").await;
    let session_a = spawn_session(&device_a, "device-b");
    // Exactly enough budget for ONE of these blocks at a time, on every one
    // of the three CONV-6 budgets `try_admit` checks at once -- so a
    // second, concurrently-requested block of the same size can only be
    // admitted if the first's `ServeCreditGuard` has already released its
    // share. Dispatch/examination capacity is left generous (4): this test
    // is not exercising either of those.
    let engine = yadorilink_peer_session::block_serve::BlockServeEngine::new(
        BLOCK_LEN as u64,
        BLOCK_LEN as u64,
        BLOCK_LEN as u64,
        4,
    );
    session_a.session.set_block_serve_engine(engine);
    // Slow enough that acquiring BLOCK_LEN bytes of upload tokens --
    // starting from a fresh bucket, whose initial burst allowance equals
    // the configured rate itself (`TokenBucket::new`'s own doc comment) --
    // takes about (BLOCK_LEN - rate) / rate = (6000 - 2000) / 2000 = 2
    // seconds.
    session_a.session.set_rate_limiters(Arc::new(RateLimiters::new(2_000, 0)));

    let started = Instant::now();
    // Both requests are left in flight on their own streams: A's answer is
    // read only after B's, which is what makes the two genuinely overlap.
    // On the old shared control stream this needed no such care because
    // every reply landed in one inbound queue; here the overlap is the
    // test's own responsibility.
    let mut request_a = begin_block_request(&requester, "device-a", "credit-a.bin", &block_a).await;

    // Well inside the ~2s throttled window above, and well after
    // `try_admit` for request A has certainly already run (a synchronous,
    // non-blocking, in-memory check) -- request B's own credit admission
    // must fail here if A's guard is still held, which is exactly what
    // forces this race deterministically rather than probabilistically.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut request_b = begin_block_request(&requester, "device-a", "credit-b.bin", &block_b).await;

    // The actual oracle below is the SEQUENCE of outcomes (Busy, then
    // Found, then Found once credit is released), not wall-clock deadlines
    // on each step -- an exact per-step timeout here previously raced a
    // real ~3.0s completion (request C's send has no initial burst credit
    // left, unlike A's) against a 3s bound with effectively zero margin.
    // This outer timeout is a watchdog against a genuine hang, not a
    // correctness check; it must stay generous relative to the ~2s
    // throttled-send window baked into the rate limiter above.
    tokio::time::timeout(Duration::from_secs(10), async {
        let (response_b, _) = read_block_response(&mut request_b).await;
        assert!(
            matches!(response_b.outcome, Some(BlockOutcome::Busy(_))),
            "request B must be denied credit admission while request A's reply is still being \
             sent (within the throttled upload window) -- if this were Found instead, \
             credit_guard was released BEFORE the send it is supposed to guard, got {:?}",
            response_b.outcome
        );
        assert!(
            started.elapsed() < Duration::from_millis(1_800),
            "request B's Busy reply must arrive well before request A's throttled send finishes \
             (~2s from `started`), proving the two were genuinely concurrent rather than \
             accidentally serialized"
        );

        let (response_a, _) = read_block_response(&mut request_a).await;
        assert!(
            matches!(response_a.outcome, Some(BlockOutcome::Found(_))),
            "request A itself must still succeed, got {:?}",
            response_a.outcome
        );

        // Now that A's reply has actually been observed, its credit must
        // already be released -- a fresh, same-sized request must succeed.
        let (response_c, _) = request_block(&requester, "device-a", "credit-c.bin", &block_c).await;
        assert!(
            matches!(response_c.outcome, Some(BlockOutcome::Found(_))),
            "request C must succeed once request A's credit_guard has released its share \
             (observed via A's own reply having already arrived), got {:?}",
            response_c.outcome
        );
    })
    .await
    .expect("credit-release scenario did not complete");
}

/// Pins invariant 4 from the peer-handler inventory doc's deep dive:
/// `shares_group` is re-checked in `handle_block_request_with_credit`
/// (~5889-5902), not just once in `handle_block_request` (~5708) --
/// already covered end to end by
/// `block_request_is_rejected_if_authorization_is_revoked_while_waiting_
/// for_a_dispatch_turn` above, which forces the exact revoked-while-
/// queued race deterministically via the same `acquire_dispatch_turn`
/// seam this file's other invariant tests use. No separate test added
/// here; this comment exists so the doc's four numbered invariants each
/// have an explicit pointer to their covering test.
///
/// Pins invariant 5: the REQUESTING side of a block exchange acquires no
/// examination, dispatch, or credit permit of any kind. Those three budgets
/// bound what this device agrees to *serve*; asking a peer for a block
/// spends none of them, and a device whose serve engine is saturated must
/// still be able to fetch. Demonstrated by fully saturating the requesting
/// session's own `BlockServeEngine` (the one it would use only if IT were
/// answering inbound requests from someone else) -- its examination-
/// admission pool, its one dispatch slot, and its one byte of credit -- for
/// the whole test, and confirming `fetch_block` still resolves promptly.
#[tokio::test]
async fn fetching_a_block_acquires_no_examination_dispatch_or_credit_permit() {
    let device_a = Device::new("device-a").await;
    let device_b = device_a.peer("device-b").await;

    let content = b"content fetched while the requester's own engine is fully starved".to_vec();
    let hash = seed_referenced_block(&device_a, "starved-requester.bin", &content);

    let _session_a = spawn_session_with_block_serve_engine(
        &device_a,
        "device-b",
        yadorilink_peer_session::block_serve::BlockServeEngine::new(
            u64::MAX,
            u64::MAX,
            u64::MAX,
            4,
        ),
    );

    // Device-b's OWN serve-side engine (used only if IT were answering
    // inbound requests from someone else), deliberately starved of every
    // permit kind for the whole test.
    let starved_engine = yadorilink_peer_session::block_serve::BlockServeEngine::new(1, 1, 1, 1);
    let session_b =
        spawn_session_with_block_serve_engine(&device_b, "device-a", starved_engine.clone());
    let mut held_examination_permits = Vec::new();
    while let Ok(permit) = starved_engine.try_begin_examination() {
        held_examination_permits.push(permit);
    }
    assert!(!held_examination_permits.is_empty(), "sanity: examination capacity must be positive");
    let _held_dispatch_guard =
        starved_engine.acquire_dispatch_turn("device-a", GROUP, 1).await.unwrap();
    let _held_credit_guard = starved_engine.try_admit("device-a", GROUP, 1).unwrap();

    let fetched = tokio::time::timeout(
        Duration::from_secs(5),
        session_b.session.fetch_block(GROUP, "starved-requester.bin", &hash),
    )
    .await
    .expect(
        "a fetch must resolve promptly regardless of this session's own (unrelated) serve-side \
         admission state",
    )
    .unwrap();

    assert_eq!(
        fetched.map(|b| b.to_vec()),
        Some(content),
        "the fetch must still succeed with the correct content"
    );
    drop(held_examination_permits);
}

/// A raw, manually-driven peer must actually receive a
/// `Compression::Zstd`-tagged, genuinely smaller body for compressible
/// content — inspecting the real wire bytes a live `handle_block_request`
/// produces, not just asserting the codec functions work standalone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_response_is_actually_compressed_on_the_wire_for_compressible_content() {
    let device_a = Device::new("device-a").await;

    // Repetitive text, sized to stay within one 128 KiB default block so
    // there's exactly one block/hash to reason about.
    let content = "the quick brown fox jumps over the lazy dog\n".repeat(2_000).into_bytes();
    assert!(content.len() < 128 * 1024, "test content must fit in a single default-size block");
    let file_path = device_a.root_path().join("big.txt");
    std::fs::write(&file_path, &content).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    let block = record.blocks.first().cloned().expect("content must chunk to at least one block");
    // Block-serving authorization requires a real PUBLISHED Change
    // backing the served path.
    device_a.publish_pending();

    let requester = device_a.fake_peer("device-b").await;
    let _session_a = spawn_session(&device_a, "device-b");

    let (response, body) = request_block(&requester, "device-a", "big.txt", &block.hash).await;
    let found = expect_found(&response);

    assert_eq!(
        found.compression,
        proto::Compression::Zstd as i32,
        "highly compressible content must be sent compressed"
    );
    assert_eq!(
        found.size as usize,
        body.len(),
        "the declared size is what is actually on the wire, post-compression"
    );
    assert!(
        body.len() < (block.size as usize) / 2,
        "compressed payload ({} bytes) should be well under half the raw block size ({} bytes) \
         for highly repetitive text",
        body.len(),
        block.size
    );
    let decompressed = zstd::stream::decode_all(body.as_slice()).unwrap();
    assert_eq!(decompressed.len(), block.size as usize);
    assert_eq!(
        sha256_bytes(&decompressed),
        block.hash,
        "decompressed wire bytes must match the block's content hash"
    );
}

/// The other half of the same decision: content that compression would
/// make *larger* is sent raw, tagged `Compression::None`.
///
/// This is what is left of the old "an unnegotiated peer never receives a
/// compressed block" test. Compression is no longer negotiated at all --
/// every peer that reaches a session understands both encodings — so
/// "the peer did not ask for it" is no longer a reason a responder can
/// have for choosing raw. The only reason left is the real one:
/// `compress_block` returns the original bytes with `COMPRESSION_NONE`
/// whenever compressing them would inflate them, which is exactly what
/// already-incompressible content does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_response_is_sent_raw_when_compressing_it_would_inflate_it() {
    let device_a = Device::new("device-a").await;

    let content = incompressible_bytes("a block compression cannot shrink", 64 * 1024);
    assert!(
        zstd::stream::encode_all(content.as_slice(), 3).unwrap().len() >= content.len(),
        "sanity: this content must genuinely be one that compression cannot shrink"
    );

    let file_path = device_a.root_path().join("random.bin");
    std::fs::write(&file_path, &content).unwrap();
    let record = expect_file_changed(
        device_a
            .processor()
            .process_event(
                GROUP,
                &device_a.root_path(),
                &FsChangeEvent { path: file_path, kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .unwrap(),
    );
    let block = record.blocks.first().cloned().expect("content must chunk to at least one block");
    // Block-serving authorization requires a real PUBLISHED Change
    // backing the served path.
    device_a.publish_pending();

    let requester = device_a.fake_peer("device-b").await;
    let _session_a = spawn_session(&device_a, "device-b");

    let (response, body) = request_block(&requester, "device-a", "random.bin", &block.hash).await;
    let found = expect_found(&response);

    assert_eq!(
        found.compression,
        proto::Compression::None as i32,
        "a block compression would only make bigger must be sent raw"
    );
    assert_eq!(
        body,
        content[..block.size as usize].to_vec(),
        "a raw block response must carry the exact block bytes, unchanged"
    );
}

#[cfg(test)]
mod reconcile_group_paths_flush_tests {
    use ed25519_dalek::SigningKey;
    use std::collections::{BTreeSet, HashMap};
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
    use yadorilink_local_capture::LocalChangeProcessor;
    use yadorilink_local_storage::SegmentBlockStore;
    use yadorilink_peer_session::peer_session::{
        ChangeAuthenticator, PeerSyncSession, PeerSyncSessionDeps, PendingLocalChangeFlush,
        PendingLocalFlushOutcome,
    };

    use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

    const GROUP: &str = "flush-guard-group";
    const REMOTE: &str = "device-remote";
    const LOCAL: &str = "device-local";

    fn remote_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn local_key() -> SigningKey {
        SigningKey::from_bytes(&[8u8; 32])
    }

    struct TestAuthenticator {
        author_verifying_key: [u8; 32],
    }
    impl ChangeAuthenticator for TestAuthenticator {
        fn resolve_authority_key(
            &self,
            _group_id: &str,
            signer_key_id: &[u8; 32],
            _policy_head: &[u8; 32],
        ) -> Option<ed25519_dalek::VerifyingKey> {
            let key = yadorilink_replica_domain::change::verifying_key_from_bytes(
                &self.author_verifying_key,
            )
            .ok()?;
            (&yadorilink_replica_domain::authorization_checkpoint::fingerprint_signing_key(&key)
                == signer_key_id)
                .then_some(key)
        }
    }

    /// Stands in for the daemon's `LinkFlushHandle`: when asked to flush a path
    /// that is marked pending, it dispatches the on-disk edit through the real
    /// `LocalChangeProcessor` emission path (index + DAG), exactly as a real
    /// debounce flush would. `pending` models what is sitting undispatched in
    /// the accumulator; `calls` records every path the session asked to flush,
    /// so a test can witness that the reconcile-site guard actually fired.
    struct RecordingFlush {
        processor: Arc<LocalChangeProcessor>,
        root: PathBuf,
        pending: Mutex<BTreeSet<String>>,
        calls: Mutex<Vec<String>>,
        /// When set, every call returns `RetryRequired` immediately instead
        /// of running its normal body -- simulates the targeted-flush
        /// channel staying permanently saturated (see
        /// `handle_change_batch_does_not_park_when_local_flush_is_saturated`),
        /// without needing a real bounded mpsc channel in this harness.
        force_retry: std::sync::atomic::AtomicBool,
    }
    impl RecordingFlush {
        fn new(processor: Arc<LocalChangeProcessor>, root: PathBuf) -> Self {
            Self {
                processor,
                root,
                pending: Mutex::new(BTreeSet::new()),
                calls: Mutex::new(vec![]),
                force_retry: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }
    impl PendingLocalChangeFlush for RecordingFlush {
        fn flush_pending_local_change<'a>(
            &'a self,
            group_id: &'a str,
            rel_path: &'a str,
        ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(rel_path.to_string());
                if self.force_retry.load(std::sync::atomic::Ordering::SeqCst) {
                    return PendingLocalFlushOutcome::RetryRequired;
                }
                // Drop the guard before the await below.
                let is_pending = self.pending.lock().unwrap().remove(rel_path);
                if is_pending {
                    let event = FsChangeEvent {
                        path: self.root.join(rel_path),
                        kind: FsChangeKind::CreatedOrModified,
                    };
                    let _ = self.processor.process_event(group_id, &self.root, &event).await;
                }
                PendingLocalFlushOutcome::Settled
            })
        }
        fn flush_case_fold_sibling<'a>(
            &'a self,
            _group_id: &'a str,
            rel_path: &'a str,
        ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
            // On a case-insensitive filesystem (e.g. the macOS test host) the
            // session also probes for a colliding sibling; this scenario stages
            // no case-fold sibling, so it is a recorded no-op.
            Box::pin(async move {
                self.calls.lock().unwrap().push(format!("casefold:{rel_path}"));
                if self.force_retry.load(std::sync::atomic::Ordering::SeqCst) {
                    return PendingLocalFlushOutcome::RetryRequired;
                }
                PendingLocalFlushOutcome::Settled
            })
        }
    }

    struct Harness {
        session: Arc<PeerSyncSession>,
        _state: Arc<ReplicaCoordinator>,
        _sync_root: PathBuf,
        /// Always wired in (see `setup`'s own doc comment): a test that never
        /// calls `flush.mark_pending` sees the exact same no-op behavior an
        /// absent handle used to produce, since `RecordingFlush` only ever
        /// dispatches a path it was told is pending.
        _flush: Arc<RecordingFlush>,
        _root_dir: tempfile::TempDir,
        _store_dir: tempfile::TempDir,
    }

    /// Builds a session with `TestAuthenticator` wired as its change
    /// authenticator (every test in this module needs to admit REMOTE's
    /// signed changes) and a `RecordingFlush` wired as its pending-local-
    /// change-flush handle, keyed to the harness's own `local_processor`/
    /// `sync_root`. The flush handle is installed unconditionally rather
    /// than only for the handful of tests that call `flush.mark_pending` --
    /// with nothing marked pending it never dispatches anything, so this is
    /// behaviorally identical to the deny-by-default no-op every other
    /// caller of `PeerSyncSessionDeps::test_permissive` gets, and
    /// lets a test install a genuinely pending edit mid-test just by calling
    /// `h.flush.mark_pending(path)` without needing the session constructed
    /// any differently.
    async fn setup() -> Harness {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        // Kept as a concrete `Arc<SegmentBlockStore>` alongside its
        // `Arc<dyn BlockContentStore>` coercion: both `LocalChangeProcessor`
        // below and `PeerSyncSession` now take the same port trait, and a
        // concrete, still-Sized `BlockStore` implementor unsize-coerces
        // straight to it (see `yadorilink_local_storage::content_ports`'s module doc).
        let fs_store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> = fs_store.clone();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &sync_root,
            GROUP,
            state.as_ref(),
        )
        .unwrap();
        // A live link always reaches Ready in a real daemon: app::run starts a
        // watcher for every link at boot, and add_link starts one immediately.
        // Peer apply for a live link that never registered a gate defers, so a
        // test that skipped this would be exercising a state the daemon does
        // not produce.
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), sync_root.clone())]);

        // The local-edit emitter shares the session's state AND block store, so
        // a flushed local edit is a live DAG head the reconcile reads and its
        // content is fetchable when materialized. Built before the session
        // (which used to be unnecessary when the flush handle was wired in
        // after the fact) since the session now needs it at construction.
        let local_processor = Arc::new(
            LocalChangeProcessor::new(
                state.clone(),
                fs_store.clone(),
                LOCAL.to_string(),
                std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
            )
            .with_change_emitter(Arc::new(ChangeEmitter::new(LOCAL, local_key()))),
        );
        let flush = Arc::new(RecordingFlush::new(local_processor.clone(), sync_root.clone()));

        let book = yadorilink_lane_ports::testing::TestAddressBook::new();
        let node_local =
            yadorilink_lane_ports::testing::TestPeerNode::start(LOCAL, book.clone()).await;
        let _node_remote = yadorilink_lane_ports::testing::TestPeerNode::start(REMOTE, book).await;
        let peer_transports = node_local.transports_for(REMOTE);
        let replica_engine =
            yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
                &state,
                store.clone(),
            );
        let session = PeerSyncSession::over_substrate(
            LOCAL.to_string(),
            REMOTE.to_string(),
            state.clone() as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
            replica_engine,
            store.clone(),
            vec![GROUP.to_string()],
            sync_roots,
            yadorilink_peer_session::ports::SessionTransports {
                blocks: peer_transports.clone(),
                service: peer_transports.clone(),
                prepared_snapshots: Arc::new(yadorilink_lane_ports::PreparedSnapshots::new()),
                snapshot_fetch: peer_transports,
            },
            None,
            PeerSyncSessionDeps {
                change_authenticator: Arc::new(TestAuthenticator {
                    author_verifying_key: remote_key().verifying_key().to_bytes(),
                }),
                pending_local_change_flush: flush.clone(),
                ..PeerSyncSessionDeps::test_permissive()
            },
        );

        Harness {
            session,
            _state: state,
            _sync_root: sync_root,
            _flush: flush,
            _root_dir: root_dir,
            _store_dir: store_dir,
        }
    }

    /// `change_emitter()` defaults to `None` -- the same safe, defined "no
    /// signing capability yet" state a session with no real change
    /// authenticator has for `change_authenticator()` -- for a session
    /// constructed with no emitter, and is `Some`, keyed to this device's
    /// own id and key, for one constructed with one wired in via
    /// `PeerSyncSessionDeps::change_emitter`.
    #[tokio::test]
    async fn change_emitter_defaults_to_none_and_is_wired_in_at_construction() {
        let h = setup().await;
        assert!(
            h.session.change_emitter().is_none(),
            "a session constructed with no emitter must have no signing capability wired"
        );

        let emitter = Arc::new(ChangeEmitter::new(LOCAL, local_key()));
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let sync_root = root_dir.path().canonicalize().unwrap();
        let store: Arc<dyn yadorilink_local_storage::BlockContentStore> =
            Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let book = yadorilink_lane_ports::testing::TestAddressBook::new();
        let node_local =
            yadorilink_lane_ports::testing::TestPeerNode::start(LOCAL, book.clone()).await;
        let _node_remote = yadorilink_lane_ports::testing::TestPeerNode::start(REMOTE, book).await;
        let peer_transports = node_local.transports_for(REMOTE);
        let with_emitter_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let with_emitter_engine =
            yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
                &with_emitter_state,
                store.clone(),
            );
        let with_emitter = PeerSyncSession::over_substrate(
            LOCAL.to_string(),
            REMOTE.to_string(),
            with_emitter_state
                as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
            with_emitter_engine,
            store,
            vec![GROUP.to_string()],
            HashMap::from([(GROUP.to_string(), sync_root)]),
            yadorilink_peer_session::ports::SessionTransports {
                blocks: peer_transports.clone(),
                service: peer_transports.clone(),
                prepared_snapshots: Arc::new(yadorilink_lane_ports::PreparedSnapshots::new()),
                snapshot_fetch: peer_transports,
            },
            None,
            PeerSyncSessionDeps {
                change_emitter: Some(emitter.clone()),
                ..PeerSyncSessionDeps::test_permissive()
            },
        );

        let installed = with_emitter
            .change_emitter()
            .expect("must be Some for a session constructed with an emitter");
        assert_eq!(installed.device_id(), LOCAL, "the installed emitter must be this device's own");
    }
}

/// The handoff-lease/handoff-ticket/re-bootstrap peer-to-peer exchange, over
/// the real service RPC lane (`yadorilink-peer-session::service_rpc`) this
/// track's Option-A cutover replaced the old shared-channel/request-id wire
/// frames with. Unlike the deleted mechanism-only unit tests these retarget
/// (which built two `PeerSyncSession`s over a bare `QuicPeerChannel` with no
/// `ServiceStreamTransport` wired -- exercising the now-deleted legacy
/// fallback, not the service lane), these use the same real substrate
/// fixture (`TestPeerNode`) the block-serving tests above already use, so a
/// request genuinely opens a service stream, is decoded, authorized, and
/// answered by `serve_service_stream`/`answer_service_request`.
mod service_rpc_wire_tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;

    use yadorilink_peer_session::peer_session::{
        HandoffLeaseResponder, HandoffTicketResponder, PeerHandoffLeaseGrant,
        PeerHandoffTicketGrant, PeerSyncSessionDeps,
    };

    const GROUP: &str = "service-rpc-group";

    /// Two devices with real substrate endpoints, no session running yet --
    /// see `spawn_rpc_session`, which builds one against a given `deps`.
    async fn rpc_device_pair() -> (Device, Device) {
        let device_a = Device::new("rpc-device-a").await;
        let device_b = device_a.peer("rpc-device-b").await;
        (device_a, device_b)
    }

    /// Builds `device`'s session for `peer_device_id`, with the substrate's
    /// real block/service/snapshot transports wired (so a service RPC this
    /// session sends genuinely crosses the wire to whichever session
    /// `peer_device_id`'s own device registers), and registers it to serve
    /// inbound streams from that peer. Service RPCs use the service lane
    /// directly (see `service_rpc`'s own doc comment -- the stream IS the
    /// correlation).
    fn spawn_rpc_session(
        device: &Device,
        peer_device_id: &str,
        deps: PeerSyncSessionDeps,
    ) -> Arc<PeerSyncSession> {
        let transports = device.node.transports_for(peer_device_id);
        let replica_engine =
            yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
                &device.state,
                device.store.clone(),
            );
        let session = PeerSyncSession::over_substrate(
            device.device_id.clone(),
            peer_device_id.to_string(),
            device.state.clone()
                as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
            replica_engine,
            device.store.clone(),
            vec![GROUP.to_string()],
            HashMap::new(),
            yadorilink_peer_session::ports::SessionTransports {
                blocks: transports.clone(),
                service: transports.clone(),
                prepared_snapshots: device.prepared_snapshots.clone(),
                snapshot_fetch: transports,
            },
            None,
            deps,
        );
        device.node.serve_with(peer_device_id, session.clone());
        session
    }

    /// A fixed-answer `HandoffLeaseResponder`: returns whatever
    /// `Option<PeerHandoffLeaseGrant>` it was constructed with, and records
    /// every release it is asked to perform.
    struct FixedLeaseResponder {
        grant: Option<PeerHandoffLeaseGrant>,
        releases: tokio::sync::mpsc::UnboundedSender<(String, String)>,
    }
    impl HandoffLeaseResponder for FixedLeaseResponder {
        fn request_handoff_lease<'a>(
            &'a self,
            _group_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffLeaseGrant>> + Send + 'a>> {
            let answer = self.grant.clone();
            Box::pin(async move { answer })
        }

        fn release_handoff_lease<'a>(
            &'a self,
            group_id: &'a str,
            lease_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let tx = self.releases.clone();
            let values = (group_id.to_string(), lease_id.to_string());
            Box::pin(async move {
                let _ = tx.send(values);
            })
        }
    }

    /// The normal-handoff path end to end: the responder's real
    /// `HandoffLeaseResponder` grants a lease over the service lane, the
    /// requester receives exactly that lease id/root digest/expiry back, and
    /// a subsequent release reaches the same responder.
    #[tokio::test]
    async fn handoff_lease_round_trips_over_the_service_rpc_lane() {
        let (device_a, device_b) = rpc_device_pair().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let expected_digest = [42u8; 32];

        let _session_b = spawn_rpc_session(
            &device_b,
            &device_a.device_id,
            PeerSyncSessionDeps {
                handoff_lease_responder: Arc::new(FixedLeaseResponder {
                    grant: Some(PeerHandoffLeaseGrant {
                        lease_id: "lease-1".to_string(),
                        root_digest: expected_digest,
                        expires_at_unix: 999,
                    }),
                    releases: tx,
                }),
                ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
            },
        );
        let session_a = spawn_rpc_session(
            &device_a,
            &device_b.device_id,
            yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone(),
        );

        let grant = session_a
            .request_handoff_lease_from_peer(GROUP)
            .await
            .expect("a responder that grants a lease must be relayed back to the requester");
        assert_eq!(grant.lease_id, "lease-1");
        assert_eq!(grant.root_digest, expected_digest);
        assert_eq!(grant.expires_at_unix, 999);

        session_a.release_handoff_lease_to_peer(GROUP, "lease-1").await.unwrap();
        let released = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("release message should arrive")
            .expect("release recorder should remain open");
        assert_eq!(released, (GROUP.to_string(), "lease-1".to_string()));
    }

    /// A request for a group the two sessions do NOT share is refused
    /// without ever consulting the responder -- the same live
    /// `shares_group` re-check every other service RPC kind applies, proven
    /// here by pointing the request at an unshared group while the
    /// responder is set up to grant unconditionally.
    #[tokio::test]
    async fn handoff_lease_request_is_refused_for_an_unshared_group() {
        let (device_a, device_b) = rpc_device_pair().await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let _session_b = spawn_rpc_session(
            &device_b,
            &device_a.device_id,
            PeerSyncSessionDeps {
                handoff_lease_responder: Arc::new(FixedLeaseResponder {
                    grant: Some(PeerHandoffLeaseGrant {
                        lease_id: "lease-should-never-be-seen".to_string(),
                        root_digest: [1u8; 32],
                        expires_at_unix: 999,
                    }),
                    releases: tx,
                }),
                ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
            },
        );
        let session_a = spawn_rpc_session(
            &device_a,
            &device_b.device_id,
            yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone(),
        );

        assert!(
            session_a.request_handoff_lease_from_peer("some-other-group").await.is_none(),
            "a group neither session shares must never yield a grant, regardless of what an \
             installed responder would otherwise answer"
        );
    }

    /// A fixed-answer `HandoffTicketResponder`, same shape as
    /// `FixedLeaseResponder`.
    struct FixedTicketResponder {
        grant: Option<PeerHandoffTicketGrant>,
        releases: tokio::sync::mpsc::UnboundedSender<(String, String, String)>,
    }
    impl HandoffTicketResponder for FixedTicketResponder {
        fn request_handoff_ticket<'a>(
            &'a self,
            _group_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = Option<PeerHandoffTicketGrant>> + Send + 'a>> {
            let answer = self.grant.clone();
            Box::pin(async move { answer })
        }

        fn release_handoff_ticket<'a>(
            &'a self,
            group_id: &'a str,
            target_device_id: &'a str,
            lease_id: &'a str,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            let tx = self.releases.clone();
            let values = (group_id.to_string(), target_device_id.to_string(), lease_id.to_string());
            Box::pin(async move {
                let _ = tx.send(values);
            })
        }
    }

    /// The removed-device-ticket path end to end, same shape as the handoff
    /// lease test above.
    #[tokio::test]
    async fn handoff_ticket_round_trips_over_the_service_rpc_lane() {
        let (device_x, device_b) = rpc_device_pair().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let _session_b = spawn_rpc_session(
            &device_b,
            &device_x.device_id,
            PeerSyncSessionDeps {
                handoff_ticket_responder: Arc::new(FixedTicketResponder {
                    grant: Some(PeerHandoffTicketGrant {
                        lease_id: Some("ticket-lease-1".to_string()),
                        target_device_id: Some("device-c".to_string()),
                        expires_at_unix: 999,
                    }),
                    releases: tx,
                }),
                ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
            },
        );
        let session_x = spawn_rpc_session(
            &device_x,
            &device_b.device_id,
            yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone(),
        );

        let grant = session_x
            .request_handoff_ticket_from_peer(GROUP)
            .await
            .expect("a responder that grants a ticket must be relayed back to the requester");
        assert_eq!(grant.lease_id.as_deref(), Some("ticket-lease-1"));
        assert_eq!(grant.target_device_id.as_deref(), Some("device-c"));
        assert_eq!(grant.expires_at_unix, 999);

        session_x
            .release_handoff_ticket_to_peer(GROUP, "device-c", "ticket-lease-1")
            .await
            .unwrap();
        let released = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("ticket release should arrive")
            .expect("release recorder should remain open");
        assert_eq!(
            released,
            (GROUP.to_string(), "device-c".to_string(), "ticket-lease-1".to_string())
        );
    }

    /// Same authorization property as `handoff_lease_request_is_refused_
    /// for_an_unshared_group`, for the ticket exchange.
    #[tokio::test]
    async fn handoff_ticket_request_is_refused_for_an_unshared_group() {
        let (device_x, device_b) = rpc_device_pair().await;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();

        let _session_b = spawn_rpc_session(
            &device_b,
            &device_x.device_id,
            PeerSyncSessionDeps {
                handoff_ticket_responder: Arc::new(FixedTicketResponder {
                    grant: Some(PeerHandoffTicketGrant {
                        lease_id: Some("ticket-should-never-be-seen".to_string()),
                        target_device_id: Some("device-c".to_string()),
                        expires_at_unix: 999,
                    }),
                    releases: tx,
                }),
                ..yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()
            },
        );
        let session_x = spawn_rpc_session(
            &device_x,
            &device_b.device_id,
            yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone(),
        );

        assert!(
            session_x.request_handoff_ticket_from_peer("some-other-group").await.is_none(),
            "a group neither session shares must never yield a grant, regardless of what an \
             installed responder would otherwise answer"
        );
    }
}
