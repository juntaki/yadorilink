//! Change-DAG convergence authority over a real peer session.
//!
//! These tests were `yadorilink-peer-session`'s until the executor they drive
//! moved into this crate. Their bodies are unchanged: what moved is ownership,
//! not behavior. The fixture they are built on lives in
//! `test_support::peer_session_fixture`, next to the `ReplicaCoordinator` it
//! is built on.

use yadorilink_daemon::test_support::peer_session_fixture::*;
#[cfg(test)]
mod dag_convergence_authority_tests {

    use yadorilink_peer_session::peer_session::{
        ChangeAuthenticator, PeerSyncSession, PeerSyncSessionDeps,
    };
    use yadorilink_replica_domain::test_authoring::create_signed_for_tests;

    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Arc;
    use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
    use yadorilink_local_storage::SegmentBlockStore;
    use yadorilink_replica_domain::change::{Change, Op, PutOrigin};
    use yadorilink_replica_domain::file::{FileMeta, FileVersion};
    use yadorilink_replica_domain::file::{FileRecord, RecordKind};
    use yadorilink_replica_domain::ids::SyncPath;
    use yadorilink_sync_sqlite::dag_store::{self, ChangeEmitter};

    const GROUP: &str = "shared-group";
    const OLD_MTIME: i64 = 1_000; // lamport WINNER carries the OLDER mtime …
    const NEW_MTIME: i64 = 9_000; // … and the mtime winner is the lamport LOSER.

    /// The version `path`'s current row actually names.
    ///
    /// A publish that names a version the row does not have is refused:
    /// evidence has to be about the row it describes, and a proof naming
    /// something the row has moved off (or never had) is exactly what
    /// that guard exists to stop. Several tests below simulate "a prior
    /// cycle already published for this path" by calling the publish
    /// primitive directly, and a simulation of a materialize has to leave
    /// what a materialize leaves -- the row included -- not just its
    /// proof.
    fn row_version(
        state: &ReplicaCoordinator,
        path: &str,
    ) -> yadorilink_replica_domain::ids::VersionHash {
        state
            .file_index_repository()
            .canonical_current_row(GROUP, path)
            .expect("canonical current row")
            .expect("the fixture must have seeded a current row for this path")
            .version_hash()
    }

    struct Harness {
        session: Arc<crate::TestPeerRuntime>,
        state: Arc<ReplicaCoordinator>,
        _root: tempfile::TempDir,
        _store_dir: tempfile::TempDir,
        root: std::path::PathBuf,
    }

    async fn harness(local: &str, peer: &str) -> Harness {
        harness_with_deps(local, peer, PeerSyncSessionDeps::test_permissive()).await
    }

    /// Like `harness`, but takes the session's 8 one-time capability
    /// injections explicitly instead of defaulting them.
    async fn harness_with_deps(
        local: &str,
        peer: &str,
        one_time_deps: PeerSyncSessionDeps,
    ) -> Harness {
        let root_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        // A live, started-up link is the only state a real daemon presents to a
        // peer session: the apply path reads the link table for every write it
        // makes, and `wait_group_ready` defers a batch for a live link whose
        // startup never registered a gate. Skipping either half here would
        // exercise a state the daemon cannot produce.
        state.link_repository().add_link(&root.to_string_lossy(), GROUP).unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(&root, GROUP, state.as_ref())
            .unwrap();
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);
        let sync_roots = HashMap::from([(GROUP.to_string(), root.clone())]);
        // Captured before both move into the session constructor, so the
        // executor beside it is built from the same store and roots.
        let store_for_executor: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
            store.clone();
        let sync_roots_for_executor = sync_roots.clone();
        let book = yadorilink_lane_ports::testing::TestAddressBook::new();
        let node_local =
            yadorilink_lane_ports::testing::TestPeerNode::start(local, book.clone()).await;
        let _node_peer = yadorilink_lane_ports::testing::TestPeerNode::start(peer, book).await;
        let peer_transports = node_local.transports_for(peer);
        let replica_engine =
            yadorilink_daemon::replica_coordinator::engine_ports::build_peer_replica_engine(
                &state,
                store.clone(),
            );
        let session = PeerSyncSession::over_substrate(
            local.to_string(),
            peer.to_string(),
            state.clone() as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
            replica_engine,
            store,
            vec![GROUP.to_string()],
            sync_roots,
            yadorilink_peer_session::ports::SessionTransports {
                blocks: peer_transports.clone(),
                service: peer_transports.clone(),
                prepared_snapshots: Arc::new(yadorilink_lane_ports::PreparedSnapshots::new()),
                snapshot_fetch: peer_transports,
            },
            None,
            one_time_deps.clone(),
        );
        let session = crate::runtime_from_parts(
            session,
            local,
            state.clone(),
            store_for_executor,
            sync_roots_for_executor,
            &one_time_deps,
        );
        Harness { session, state, _root: root_dir, _store_dir: store_dir, root }
    }

    fn empty_record(path: &str, mtime: i64) -> FileRecord {
        FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos: mtime,
            blocks: vec![],
            deleted: false,
        }
    }

    /// Authoring identity is mandatory: an identity-less projected record is
    /// rejected instead of falling back to an empty version vector.
    #[tokio::test]
    async fn projected_rows_without_authoring_identity_are_rejected() {
        let h = harness("device-local", "device-p").await;
        let local = empty_record("split.txt", OLD_MTIME);
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &local,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let incoming = empty_record("split.txt", NEW_MTIME);
        let meta = yadorilink_daemon::local_convergence::types::IncomingWireMeta {
            xattrs: Vec::new(),
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: None,
            origin_device_id: None,
            authoring_change_hash: None,
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let error = match h
            .session
            .convergence
            .apply_locked_record(&h.session.driver(), GROUP, incoming, meta, policy)
            .await
        {
            Ok(_) => panic!("missing authoring identity must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(error, yadorilink_peer_session::error::PeerSessionError::InvalidInput(_)));
        let record = h
            .state
            .file_index_repository()
            .get_file(GROUP, "split.txt")
            .unwrap()
            .expect("row still present");
        assert_eq!(
            record.mtime_unix_nanos, OLD_MTIME,
            "neither side may be adopted by the legacy exchange -- the DAG decides"
        );
    }

    /// A `Placeholder` row with no authoring identity yet -- the shape a
    /// bootstrap scaffold or a rebootstrap-from-snapshot import can
    /// legitimately leave behind before it is paired with real content --
    /// must not abort the whole materialization audit attempt. Before the
    /// fix this pins, `list_materialization_repair_candidates` selecting
    /// this row (correct: it does need materializing eventually) fed
    /// straight into `file_info_for_record`'s `CorruptState` on the
    /// missing identity, failing the entire audit call -- for every OTHER
    /// candidate path in the same group, not just this one.
    #[tokio::test]
    async fn audit_skips_a_not_yet_paired_candidate_instead_of_erroring() {
        let h = harness("device-local", "device-p").await;
        h.state
            .link_repository()
            .set_materialization_policy(
                &h.root.to_string_lossy(),
                yadorilink_replica_domain::session_state::MaterializationPolicy::Eager,
            )
            .unwrap();
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        h.state
            .file_index_repository()
            .upsert_file(GROUP, &empty_record("scaffold.txt", OLD_MTIME), &permit)
            .unwrap();
        h.state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "scaffold.txt",
                yadorilink_replica_domain::session_state::MaterializationState::Placeholder,
                &permit,
            )
            .unwrap();
        // Deliberately no authoring_change_hash -- `upsert_file` never sets
        // one, matching both real production writers that can leave a
        // `Placeholder` row in this exact shape.

        let candidates = h
            .state
            .materialization_state_repository()
            .list_materialization_repair_candidates(GROUP)
            .unwrap();
        assert_eq!(
            candidates,
            vec!["scaffold.txt".to_string()],
            "sanity: the row must actually be a repair candidate for this test to exercise the \
             skip path, not something else entirely"
        );

        let result = h
            .session
            .convergence
            .clone()
            .reconcile_local_materialization_audit(&h.session.driver(), GROUP)
            .await;

        assert!(
            matches!(result, Ok(true)),
            "a not-yet-paired candidate must be skipped, not abort the whole audit attempt: {result:?}"
        );
        let row = h.state.file_index_repository().get_file(GROUP, "scaffold.txt").unwrap().unwrap();
        assert!(!row.deleted, "the scaffold row itself must be left untouched by the skip");
    }

    /// `apply_locked_record`'s own
    /// `Equal`-authoring branch (and `authoring_proves_redundant`'s own
    /// batched fast path, `rematerialize_local_records`'s only skip
    /// mechanism) used to trust `same_record_content` alone -- content
    /// equality never proved `record_kind`/`symlink_target`/`unix_mode`
    /// hadn't independently diverged (an interrupted `apply_unix_mode`, or
    /// any other way the index/disk end up out of step with the identical,
    /// already-admitted DAG version's own metadata). Reached the materia-
    /// lization-audit way (`reconcile_local_materialization_audit` ->
    /// `rematerialize_local_records` -> `apply_locked_record`), not the
    /// primary DAG-admission path -- this is the backstop that repairs
    /// exactly this class of drift, and it must not just detect it and
    /// fall through as if fully settled.
    #[tokio::test]
    async fn equal_authoring_repairs_a_diverged_unix_mode() {
        let h = harness("device-local", "device-p").await;
        let out_path = h.root.join("run.sh");
        std::fs::write(&out_path, b"").unwrap();

        let key = SigningKey::from_bytes(&[3u8; 32]);
        let version = FileVersion::from_index_row(
            vec![],
            0,
            OLD_MTIME,
            RecordKind::File,
            Some(0o755), // the DAG version itself says executable
            None,
            Vec::new(),
        );
        let change = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("run.sh".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change, std::slice::from_ref(&version))
            .unwrap();
        let author = yadorilink_replica_domain::ids::ChangeHash(change.compute_hash().0);

        // This device already applied this exact version's content, but
        // its own exec bit (index AND disk) has drifted to non-executable
        // -- simulating an interrupted `apply_unix_mode`, with nothing
        // else about the record having changed.
        h.state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                GROUP,
                &FileRecord {
                    path: "run.sh".into(),
                    size: 0,
                    mtime_unix_nanos: OLD_MTIME,
                    blocks: vec![],
                    deleted: false,
                },
                "device-p",
                &author,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        h.state
            .file_index_repository()
            .set_unix_mode(
                GROUP,
                "run.sh",
                Some(0o644),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let incoming = FileRecord {
            path: "run.sh".into(),
            size: 0,
            mtime_unix_nanos: OLD_MTIME,
            blocks: vec![],
            deleted: false,
        };
        let meta = yadorilink_daemon::local_convergence::types::IncomingWireMeta {
            xattrs: Vec::new(),
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: Some(0o755),
            origin_device_id: None,
            authoring_change_hash: Some(author),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let outcome = h
            .session
            .convergence
            .apply_locked_record(&h.session.driver(), GROUP, incoming, meta, policy)
            .await
            .unwrap();

        assert!(
            matches!(
                outcome,
                yadorilink_daemon::local_convergence::types::LockedRecordOutcome::Settled
            ),
            "an equal-authoring repair must settle, not error or defer: {outcome:?}"
        );
        assert_eq!(
            h.state.file_index_repository().get_unix_mode(GROUP, "run.sh").unwrap(),
            Some(0o755),
            "the index's own exec bit must be repaired to match the authoring change's version"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
            assert_ne!(mode & 0o100, 0, "the real on-disk file's exec bit must be repaired too");
        }
    }

    /// `apply_locked_record`'s `Equal`-arm
    /// metadata repair (the sibling of the test above, same drift shape --
    /// see that test's own setup) used to `apply_unix_mode`/`apply_xattrs`
    /// with no preceding mutation-fence bump, unlike every other
    /// `apply_unix_mode`/`apply_xattrs` call site in this crate. A real
    /// mutating syscall that runs without first bumping the fence leaves
    /// any ALREADY-PUBLISHED proof for this path wrongly current -- a
    /// later consumer that trusts `path_materialized_generations` for this
    /// path would be told disk matches evidence published before this
    /// repair ever touched it. This proves the fence value genuinely
    /// advances across the repair, using the exact same diverged-unix-mode
    /// setup the sibling test already exercises.
    #[tokio::test]
    async fn equal_authoring_metadata_repair_bumps_the_mutation_fence_before_writing() {
        let h = harness("device-local", "device-p").await;
        let out_path = h.root.join("run.sh");
        std::fs::write(&out_path, b"").unwrap();

        let key = SigningKey::from_bytes(&[3u8; 32]);
        let version = FileVersion::from_index_row(
            vec![],
            0,
            OLD_MTIME,
            RecordKind::File,
            Some(0o755),
            None,
            Vec::new(),
        );
        let change = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("run.sh".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change, std::slice::from_ref(&version))
            .unwrap();
        let author = yadorilink_replica_domain::ids::ChangeHash(change.compute_hash().0);

        h.state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                GROUP,
                &FileRecord {
                    path: "run.sh".into(),
                    size: 0,
                    mtime_unix_nanos: OLD_MTIME,
                    blocks: vec![],
                    deleted: false,
                },
                "device-p",
                &author,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        h.state
            .file_index_repository()
            .set_unix_mode(
                GROUP,
                "run.sh",
                Some(0o644),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // `dag_snapshot_mutation_fence` never bumps -- calling it here
        // reads (and, on the very first call for this path, durably seeds)
        // the CURRENT live fence value without itself being a mutation.
        let fence_before = h.state.dag_snapshot_mutation_fence(GROUP, "run.sh").unwrap();

        let incoming = FileRecord {
            path: "run.sh".into(),
            size: 0,
            mtime_unix_nanos: OLD_MTIME,
            blocks: vec![],
            deleted: false,
        };
        let meta = yadorilink_daemon::local_convergence::types::IncomingWireMeta {
            xattrs: Vec::new(),
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: Some(0o755),
            origin_device_id: None,
            authoring_change_hash: Some(author),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let outcome = h
            .session
            .convergence
            .apply_locked_record(&h.session.driver(), GROUP, incoming, meta, policy)
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                yadorilink_daemon::local_convergence::types::LockedRecordOutcome::Settled
            ),
            "an equal-authoring repair must settle, not error or defer: {outcome:?}"
        );

        let fence_after = h.state.dag_snapshot_mutation_fence(GROUP, "run.sh").unwrap();
        assert!(
            fence_after > fence_before,
            "a real fsetxattr/chmod-class repair syscall must bump the mutation fence BEFORE it \
             runs -- fence_before={fence_before}, fence_after={fence_after}. Left unbumped, an \
             already-published proof for this path stays wrongly current across a real physical \
             mutation, which is exactly the class of bug complete_obligation_if_exact_proof_\
             current's own defense-in-depth clause (c) exists to catch."
        );
    }

    /// Seeds the shape the `Equal`-arm metadata repair finds on a
    /// real device: a `Hydrated`, OnDemand, unpinned `run.sh` whose bytes
    /// are the authoring change's, whose exec bit (index AND disk) drifted
    /// to 0o644 while the admitted version says 0o755, and whose proof,
    /// published by the materialize that wrote it, names the row's 0o644
    /// version and stands under the live fence. `disk_bytes` is what is
    /// on disk. Returns the incoming record and wire metadata to apply.
    fn seed_hydrated_row_with_drifted_mode(
        h: &Harness,
        content: &[u8],
        disk_bytes: &[u8],
    ) -> (FileRecord, yadorilink_daemon::local_convergence::types::IncomingWireMeta) {
        seed_hydrated_row_with_drifted_mode_to(h, content, disk_bytes, 0o755)
    }

    /// As [`seed_hydrated_row_with_drifted_mode`], with the admitted
    /// version's mode `version_mode` instead of 0o755.
    fn seed_hydrated_row_with_drifted_mode_to(
        h: &Harness,
        content: &[u8],
        disk_bytes: &[u8],
        version_mode: u32,
    ) -> (FileRecord, yadorilink_daemon::local_convergence::types::IncomingWireMeta) {
        use sha2::Digest;
        use std::os::unix::fs::PermissionsExt;
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        h.state
            .link_repository()
            .set_materialization_policy(
                &h.root.to_string_lossy(),
                yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
            )
            .unwrap();
        let blocks = vec![yadorilink_replica_domain::file::BlockInfo {
            hash: sha2::Sha256::digest(content).to_vec(),
            offset: 0,
            size: content.len() as u32,
        }];
        let record = FileRecord {
            path: "run.sh".into(),
            size: content.len() as u64,
            mtime_unix_nanos: OLD_MTIME,
            blocks: blocks.clone(),
            deleted: false,
        };
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let version = FileVersion::from_index_row(
            blocks,
            content.len() as u64,
            OLD_MTIME,
            RecordKind::File,
            Some(version_mode),
            None,
            Vec::new(),
        );
        let change = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("run.sh".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change, std::slice::from_ref(&version))
            .unwrap();
        let author = yadorilink_replica_domain::ids::ChangeHash(change.compute_hash().0);
        h.state
            .file_index_repository()
            .upsert_file_with_origin_and_author(GROUP, &record, "device-p", &author, &permit)
            .unwrap();
        h.state
            .file_index_repository()
            .set_unix_mode(GROUP, "run.sh", Some(0o644), &permit)
            .unwrap();
        let out_path = h.root.join("run.sh");
        std::fs::write(&out_path, disk_bytes).unwrap();
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        h.state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                "run.sh",
                yadorilink_replica_domain::session_state::MaterializationState::Hydrated,
                &permit,
            )
            .unwrap();
        let frontier = h.state.sqlite().dag_group_heads(GROUP).unwrap();
        let fence = h.state.dag_snapshot_mutation_fence(GROUP, "run.sh").unwrap();
        assert!(
            h.state
                .dag_publish_materialized_generation_if_fence_current(
                    GROUP,
                    "run.sh",
                    &frontier,
                    yadorilink_peer_session::ports::ExactActualState::Object {
                        kind: RecordKind::File,
                        version: row_version(&h.state, "run.sh"),
                        identity: Box::new(Some(
                            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
                                &out_path,
                            )
                            .unwrap(),
                        )),
                    },
                    fence,
                    &permit,
                )
                .unwrap(),
            "sanity: the simulated materialize's proof must publish"
        );
        assert!(
            h.state.sqlite().dag_usable_proof_names_current_version(GROUP, "run.sh").unwrap(),
            "sanity: before the repair the row is Hydrated with a usable proof of its version"
        );
        let meta = yadorilink_daemon::local_convergence::types::IncomingWireMeta {
            xattrs: Vec::new(),
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: Some(version_mode),
            origin_device_id: None,
            authoring_change_hash: Some(author),
        };
        (record, meta)
    }

    async fn apply_equal_authoring_repair(
        h: &Harness,
        incoming: FileRecord,
        meta: yadorilink_daemon::local_convergence::types::IncomingWireMeta,
    ) {
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let outcome = h
            .session
            .convergence
            .apply_locked_record(&h.session.driver(), GROUP, incoming, meta, policy)
            .await
            .unwrap();
        assert!(
            matches!(
                outcome,
                yadorilink_daemon::local_convergence::types::LockedRecordOutcome::Settled
            ),
            "an equal-authoring repair must settle, not error or defer: {outcome:?}"
        );
    }

    /// The equal-authoring File repair bumped the mutation fence
    /// before its chmod and then published nothing, so a `Hydrated` row
    /// whose bytes it had just made exactly the version's was left with
    /// no usable proof. On an OnDemand, unpinned path nothing in the
    /// convergence lane re-drives it (`live_record_needs_rehydrate` wants
    /// no content there), and `hydrate_inner` refuses exactly that pair
    /// -- `Hydrated`, no usable generation -- as `CorruptState`, so every
    /// open and pin of the file failed until the next live repair sweep
    /// re-proved it (up to `MATERIALIZATION_REPAIR_INTERVAL`, and never
    /// while the link is stopped). The repair now proves what it verified,
    /// under the fence value its own bump returned.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_equal_authoring_metadata_repair_leaves_its_hydrated_row_proven() {
        let h = harness("device-local", "device-p").await;
        let content = b"#!/bin/sh\necho repaired\n";
        let (incoming, meta) = seed_hydrated_row_with_drifted_mode(&h, content, content);
        let fence_before = h.state.dag_snapshot_mutation_fence(GROUP, "run.sh").unwrap();

        apply_equal_authoring_repair(&h, incoming, meta).await;

        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(h.root.join("run.sh")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755, "the repair must still apply the version's mode");
        }
        assert!(
            h.state.dag_snapshot_mutation_fence(GROUP, "run.sh").unwrap() > fence_before,
            "the chmod must still be preceded by a fence bump"
        );
        assert_eq!(
            h.state.get_materialization_state(GROUP, "run.sh").unwrap(),
            Some(yadorilink_replica_domain::session_state::MaterializationState::Hydrated),
        );
        assert!(
            h.state.sqlite().dag_usable_proof_names_current_version(GROUP, "run.sh").unwrap(),
            "an equal-authoring metadata repair left its Hydrated row with no usable proof of \
             the version it repaired to (usable generation present: {}); access hydration \
             refuses that row as CorruptState",
            h.state.sqlite().dag_lookup_materialized_generation(GROUP, "run.sh").unwrap().is_some()
        );
    }

    /// The fix's fail-closed half: the repair proves only bytes it
    /// compared. When disk holds something else (an edit the watcher has
    /// not journalled yet), the chmod still runs under its bump, and the
    /// row is left without a proof, the state access hydration refuses
    /// to reconstruct over, rather than a proof that would vouch for the
    /// edit as the version.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_equal_authoring_metadata_repair_never_proves_bytes_that_are_not_the_version() {
        let h = harness("device-local", "device-p").await;
        let content = b"#!/bin/sh\necho repaired\n";
        let (incoming, meta) =
            seed_hydrated_row_with_drifted_mode(&h, content, b"#!/bin/sh\necho local edit\n");

        apply_equal_authoring_repair(&h, incoming, meta).await;

        assert!(
            !h.state.sqlite().dag_usable_proof_names_current_version(GROUP, "run.sh").unwrap(),
            "a repair over bytes that are not the version must not prove them"
        );
        assert_eq!(
            std::fs::read(h.root.join("run.sh")).unwrap(),
            b"#!/bin/sh\necho local edit\n",
            "the unjournalled edit must be left on disk"
        );
    }

    /// The re-proof reads the file's bytes, and the version being repaired
    /// to may leave it unreadable to its owner (a write-only 0o200 mode).
    /// A read that fails there must leave the row unproven, as a mismatch
    /// does, not fail the record: `apply_locked_record` would otherwise
    /// fail on every pass for a mode the version legitimately carries.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_equal_authoring_metadata_repair_to_an_unreadable_mode_still_settles() {
        use std::os::unix::fs::PermissionsExt;
        let h = harness("device-local", "device-p").await;
        let probe = h.root.join("read-probe");
        std::fs::write(&probe, b"x").unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o200)).unwrap();
        let running_as_root = std::fs::read(&probe).is_ok();
        std::fs::remove_file(&probe).unwrap();
        if running_as_root {
            // Nothing is unreadable to root, so there is nothing to test.
            return;
        }
        let content = b"#!/bin/sh\necho write-only\n";
        let (incoming, meta) = seed_hydrated_row_with_drifted_mode_to(&h, content, content, 0o200);

        apply_equal_authoring_repair(&h, incoming, meta).await;

        let out_path = h.root.join("run.sh");
        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode & 0o777, 0o200, "the repair must still apply the version's mode");
        assert!(
            !h.state.sqlite().dag_usable_proof_names_current_version(GROUP, "run.sh").unwrap(),
            "bytes the repair could not read must not be proven"
        );
    }

    /// The same repair offered again once the file already carries the
    /// owner-unreadable mode. Its attributes can be neither read nor set
    /// any more, so the repair cannot be proved, and it used to bump the
    /// fence and fail as `ReplicatedXattrsNotExact` on every pass. It must
    /// hold the path instead, decided before anything is mutated: the
    /// record settles (never a raw permission error), the fence is not
    /// bumped, the file is left exactly as it is (same inode, no chmod, same
    /// bytes), no proof is published, and the hold carries the reason
    /// status shows.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn repeating_the_repair_on_an_already_unreadable_file_holds_it_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let h = harness("device-local", "device-p").await;
        let probe = h.root.join("read-probe");
        std::fs::write(&probe, b"x").unwrap();
        std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o200)).unwrap();
        let running_as_root = std::fs::read(&probe).is_ok();
        std::fs::remove_file(&probe).unwrap();
        if running_as_root {
            return;
        }
        let content = b"#!/bin/sh\necho write-only\n";
        let (incoming, meta) = seed_hydrated_row_with_drifted_mode_to(&h, content, content, 0o200);
        apply_equal_authoring_repair(&h, incoming.clone(), meta.clone()).await;
        // Drift the index again so the second pass really runs the repair
        // against a file that is now 0o200 on disk; with the index already
        // matching, the repair block would be skipped and this test would
        // exercise nothing.
        h.state
            .file_index_repository()
            .set_unix_mode(
                GROUP,
                "run.sh",
                Some(0o644),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let out_path = h.root.join("run.sh");
        let identity_before =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
        let fence_before = h.state.dag_snapshot_mutation_fence(GROUP, "run.sh").unwrap();

        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let again = h
            .session
            .convergence
            .apply_locked_record(&h.session.driver(), GROUP, incoming, meta, policy)
            .await;

        let identity_after =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).unwrap();
        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            matches!(
                again,
                Ok(yadorilink_daemon::local_convergence::types::LockedRecordOutcome::Settled)
            ),
            "a repair that cannot read or set the attributes of an already unreadable file \
             must settle by holding it, not fail or retry: {again:?}"
        );
        assert_eq!(
            h.state
                .materialization_state_repository()
                .get_held_state(GROUP, "run.sh")
                .unwrap()
                .map(|held| held.reason),
            Some(yadorilink_peer_session::hazard::metadata_unprovable_reason()),
        );
        assert_eq!(
            h.state.dag_snapshot_mutation_fence(GROUP, "run.sh").unwrap(),
            fence_before,
            "a held repair must not bump the fence"
        );
        assert_eq!(identity_after.object_id, identity_before.object_id);
        assert_eq!(
            identity_after.metadata_fingerprint, identity_before.metadata_fingerprint,
            "a held repair must not touch the file (mode, mtime, ctime)"
        );
        assert_eq!(std::fs::read(&out_path).unwrap(), content);
        assert!(
            !h.state.sqlite().dag_usable_proof_names_current_version(GROUP, "run.sh").unwrap(),
            "a held repair must not prove a version it could not confirm"
        );
    }

    /// A permanently policy-skipped symlink (here: no target recorded --
    /// the same platform-independent `PolicySkipped` trigger the Windows-
    /// opt-in case shares) retries `materialize` on a capped backoff that
    /// is never dead-lettered. Each retry used to unconditionally re-
    /// upsert the record even when the authored version had not changed
    /// since the previous attempt -- `upsert_file_in_tx`'s own INSERT is
    /// unconditional, so a long-lived policy skip accumulated an unbounded
    /// number of no-op `version_seq` rows purely from retrying. Calling
    /// `materialize` twice for the identical authored version must not
    /// create a second version row.
    #[tokio::test]
    async fn a_repeated_policy_skipped_symlink_retry_does_not_grow_the_version_history() {
        let h = harness("device-local", "device-p").await;

        let key = SigningKey::from_bytes(&[9u8; 32]);
        // Admitted as `RecordKind::File` at the DAG/version-history layer
        // (matching the version-admission shape the sibling fence-bump
        // test above already exercises successfully) -- what actually
        // drives `materialize`'s dispatch to the symlink branch and
        // `materialize_symlink_at`'s own target lookup is the INDEX's
        // current `record_kind`/`symlink_target`, set separately below via
        // `set_record_kind`, not this admitted version's own kind field.
        let version = FileVersion::from_index_row(
            vec![],
            0,
            OLD_MTIME,
            RecordKind::File,
            None,
            None,
            Vec::new(),
        );
        let change = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("mystery-link".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change, std::slice::from_ref(&version))
            .unwrap();
        let author = yadorilink_replica_domain::ids::ChangeHash(change.compute_hash().0);

        let record = FileRecord {
            path: "mystery-link".into(),
            size: 0,
            mtime_unix_nanos: OLD_MTIME,
            blocks: vec![],
            deleted: false,
        };
        h.state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                GROUP,
                &record,
                "device-p",
                &author,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        h.state
            .file_index_repository()
            .set_record_kind(
                GROUP,
                "mystery-link",
                RecordKind::Symlink,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // Deliberately no `set_symlink_target` call -- the platform-
        // independent `PolicySkipped` trigger.

        for _ in 0..3 {
            let outcome = h
                .session
                .convergence
                .materialize(
                    &h.session.driver(),
                    GROUP,
                    &crate::symlink_payload_for(&record, None),
                    yadorilink_replica_domain::session_state::MaterializationPolicy::Eager,
                    "device-p",
                    Some(&author),
                )
                .await
                .unwrap();
            assert!(
                matches!(
                    outcome,
                    yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired
                ),
                "expected a retriable PolicySkipped outcome on every retry, got {outcome:?}"
            );
        }

        let versions = h.state.sqlite().dag_list_versions(GROUP, "mystery-link").unwrap();
        assert_eq!(
            versions.len(),
            1,
            "three retries of the identical already-authored version must never create more \
             than the one real version row -- got {versions:?}"
        );
    }

    /// The materialization-audit backstop must keep repairing missing on-disk
    /// content for records this device already holds — on a change-DAG session —
    /// via the materialize-only `rematerialize_local_records` routine. This is
    /// the audit path that stays after the second convergence engine is gone; it
    /// only ever materializes what the DAG already projected, never resolves a
    /// concurrent edit.
    #[tokio::test]
    async fn materialization_audit_runs_on_dag_session() {
        let h = harness("device-d", "device-p").await;
        // An indexed (empty-content) record whose on-disk file is missing — the
        // shape the audit exists to repair.
        let rec = empty_record("audit.txt", OLD_MTIME);
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &rec,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let emitter = ChangeEmitter::new("device-d", SigningKey::from_bytes(&[41; 32]));
        let author = h
            .state
            .append_history_backfill(
                GROUP,
                vec![Op::Delete { path: SyncPath("audit.txt".to_string()) }],
                &[],
                &emitter,
            )
            .unwrap();
        h.state
            .file_index_repository()
            .set_authoring_change_hash(GROUP, "audit.txt", &author)
            .unwrap();
        let on_disk = h.root.join("audit.txt");
        assert!(!on_disk.exists(), "precondition: the file is not yet materialized");

        let file_info = match h
            .session
            .convergence
            .materialization_audit_candidate(GROUP, "audit.txt")
            .unwrap()
        {
            yadorilink_daemon::local_convergence::types::AuditCandidate::Payload(record, meta) => {
                (record, meta)
            }
            other => panic!("the seeded row must produce an audit payload, got {other:?}"),
        };
        h.session
            .convergence
            .clone()
            .rematerialize_local_records(&h.session.driver(), GROUP, vec![file_info])
            .await
            .unwrap();

        assert!(on_disk.exists(), "the audit must re-materialize the missing file");
    }

    /// The under-lock freshness check's other arm: when the winner has moved
    /// to a NEWER content head (not a tombstone) while the caller waited for
    /// the path lock, the materialize must upgrade in place — writing the
    /// fresh winner's content immediately rather than declining and paying a
    /// full decline→retry→re-resolve round-trip under exactly the contention
    /// that produces these races.
    #[tokio::test]
    async fn a_stale_content_materialize_upgrades_to_the_newer_winner_in_place() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[1u8; 32]);
        let version_old = empty_version(OLD_MTIME);
        let change_old = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_old.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_old, std::slice::from_ref(&version_old))
            .unwrap();
        // A newer change by the same author supersedes it while the stale
        // caller is (conceptually) waiting for the lock.
        let version_new = empty_version(NEW_MTIME);
        let change_new = create_signed_for_tests(
            vec![change_old.compute_hash()],
            change_old.lamport,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_new.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_new, std::slice::from_ref(&version_new))
            .unwrap();

        let stale_head = yadorilink_replica_engine::conflict::PathHead {
            change_hash: change_old.compute_hash().0,
            lamport: change_old.lamport,
            device_id: "device-a".into(),
            // Ordinary put: the signer wrote the content, so the carrier and
            // the naming identity are the same device.
            naming_device_id: "device-a".into(),
            content: Some(yadorilink_replica_engine::conflict::PathHeadContent {
                version_hash: version_old.version_hash.0,
                mtime_unix_nanos: version_old.meta.mtime_unix_nanos,
            }),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let result = h
            .session
            .convergence
            .materialize_dag_content_head(
                GROUP,
                "shared.bin",
                "shared.bin",
                &stale_head,
                policy,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(
            matches!(
                result,
                yadorilink_daemon::local_convergence::types::MaterializeResult::Settled(_)
            ),
            "the upgraded materialize must settle, not defer to a retry"
        );
        let record = h
            .state
            .file_index_repository()
            .get_file(GROUP, "shared.bin")
            .unwrap()
            .expect("record exists");
        assert_eq!(
            record.mtime_unix_nanos, version_new.meta.mtime_unix_nanos,
            "the CURRENT winner's version must be what actually landed, not the stale head's"
        );
        assert!(h.root.join("shared.bin").exists(), "the fresh winner's file must be on disk");
    }

    /// Regression for the stale-materialize resurrection race (reproduced
    /// by three-device mesh chaos seed 1000005):
    /// a projection attempt resolves a path's winner, and BEFORE its
    /// materialize acquires the path lock, this device's user deletes the
    /// file — the local tombstone change, index row, and disk removal all
    /// land first. The stale materialize then ran anyway, re-creating the
    /// file and clobbering the tombstone's index row; and because the
    /// tombstone was locally authored (already `applied`), no reprojection
    /// ever re-examined the path — a deterministic, permanent divergence
    /// (the traced device kept a live file every peer had deleted, under
    /// byte-identical DAG heads). The materialize must re-validate the
    /// resolution under the path lock and decline to write a head that is
    /// no longer the current winner.
    #[tokio::test]
    async fn a_stale_content_materialize_must_not_resurrect_a_newer_local_tombstone() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[1u8; 32]);
        let version_w = empty_version(OLD_MTIME);
        let change_w = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_w.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_w, std::slice::from_ref(&version_w))
            .unwrap();
        h.session
            .convergence
            .reconcile_paths_directly(
                &h.session.driver(),
                GROUP,
                std::collections::BTreeSet::from(["shared.bin".to_string()]),
            )
            .await
            .unwrap()
            .expect("audit guard must be free");
        assert!(h.root.join("shared.bin").exists(), "precondition: the winner materialized");

        // The user deletes the file. Mirror the local-change pipeline's end
        // state exactly: tombstone change admitted as already-applied, index
        // row deleted, file gone from disk.
        let key_local = SigningKey::from_bytes(&[9u8; 32]);
        let change_t = create_signed_for_tests(
            vec![change_w.compute_hash()],
            change_w.lamport,
            yadorilink_replica_domain::ids::DeviceId("device-local".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("shared.bin".into()),
            }],
            &key_local,
        );
        h.state.change_history_repository().dag_admit_change(&change_t).unwrap();
        std::fs::remove_file(h.root.join("shared.bin")).unwrap();
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "shared.bin".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: true,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // The raced attempt: a materialize whose resolution predates the
        // tombstone finally gets the path lock and runs.
        let stale_head = yadorilink_replica_engine::conflict::PathHead {
            change_hash: change_w.compute_hash().0,
            lamport: change_w.lamport,
            device_id: "device-a".into(),
            // Ordinary put: the signer wrote the content, so the carrier and
            // the naming identity are the same device.
            naming_device_id: "device-a".into(),
            content: Some(yadorilink_replica_engine::conflict::PathHeadContent {
                version_hash: version_w.version_hash.0,
                mtime_unix_nanos: version_w.meta.mtime_unix_nanos,
            }),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let result = h
            .session
            .convergence
            .materialize_dag_content_head(
                GROUP,
                "shared.bin",
                "shared.bin",
                &stale_head,
                policy,
                None,
                None,
            )
            .await
            .unwrap();

        assert!(
            !h.root.join("shared.bin").exists(),
            "a stale materialize must not resurrect a file a newer local tombstone removed"
        );
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, "shared.bin")
                .unwrap()
                .is_none_or(|r| r.deleted),
            "the tombstone's index row must survive the stale attempt"
        );
        assert!(
            matches!(
                result,
                yadorilink_daemon::local_convergence::types::MaterializeResult::RetryRequired
            ),
            "a declined stale write must not report the path as settled"
        );
    }

    /// Fully filesystem-independent (no case-fold/normalization probe
    /// involved, so it runs identically on every CI runner): a tombstone
    /// for a path this device has never seen must not leave the incoming
    /// wire metadata's kind/target/exec-bit on the landed row.
    /// `apply_locked_record`'s never-seen branch used to call
    /// `apply_incoming_wire_metadata` unconditionally before `materialize`,
    /// which bootstraps a `version_seq = 0` scaffold row and stamps it with
    /// the incoming meta; `upsert_file_in_tx`'s scaffold-promotion path
    /// then carries that stamped `record_kind`/`symlink_target`/`unix_mode`
    /// forward onto the real, landed tombstone row -- meaningless metadata
    /// (a delete has no kind) baked permanently into a deleted record. A
    /// tombstone with no genuine local history reaching a hazard hold and
    /// leaving that same scaffold behind unpromoted (see `peer_session`'s
    /// own `hazardous_tombstone_for_a_bootstrap_only_scaffold_is_not_held`)
    /// is the more severe half of this same root cause, but this half
    /// needs no filesystem probe to reproduce.
    #[tokio::test]
    async fn a_never_seen_tombstone_does_not_leak_wire_metadata_onto_its_landed_row() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[3u8; 32]);
        let change_t = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("gone.txt".into()),
            }],
            &key_a,
        );
        h.state.change_history_repository().dag_admit_change(&change_t).unwrap();

        assert!(
            h.state.file_index_repository().get_file(GROUP, "gone.txt").unwrap().is_none(),
            "precondition: no prior row at all for this path"
        );

        let incoming = FileRecord {
            path: "gone.txt".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let meta = yadorilink_daemon::local_convergence::types::IncomingWireMeta {
            xattrs: Vec::new(),
            record_kind: RecordKind::Symlink,
            symlink_target: Some(b"/somewhere-meaningless".to_vec()),
            symlink_out_of_root: true,
            unix_mode: Some(0o755),
            origin_device_id: None,
            authoring_change_hash: Some(yadorilink_replica_domain::ids::ChangeHash(
                change_t.compute_hash().0,
            )),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        h.session
            .convergence
            .apply_locked_record(&h.session.driver(), GROUP, incoming, meta, policy)
            .await
            .unwrap();

        assert_eq!(
            h.state.file_index_repository().get_file(GROUP, "gone.txt").unwrap().map(|r| r.deleted),
            Some(true),
            "the tombstone itself must still land"
        );
        assert_eq!(
            h.state.file_index_repository().get_record_kind(GROUP, "gone.txt").unwrap(),
            Some(RecordKind::File),
            "a tombstone's landed row must not inherit the incoming wire meta's record_kind \
             (Symlink) -- a delete has no kind to materialize, so this must stay the column's \
             own default"
        );
        assert_eq!(
            h.state.file_index_repository().get_symlink_target(GROUP, "gone.txt").unwrap(),
            None,
            "nor the incoming wire meta's symlink_target"
        );
        assert_eq!(
            h.state.file_index_repository().get_unix_mode(GROUP, "gone.txt").unwrap(),
            None,
            "nor the incoming wire meta's unix_mode"
        );
    }

    /// `reconcile_group_paths`'s `PathResolution::Absent` branch used to
    /// fold every `Ok(_)` from `materialize` into `settled`, unlike the
    /// `Present` branch a few lines below it, which has always distinguished
    /// `Settled` from `RetryRequired`. A hazard-collision tombstone that
    /// drops without applying anything (see the `version_hash_exact_
    /// capability_tests` module's `hazardous_tombstone_for_a_bootstrap_
    /// only_scaffold_is_not_held`, which proves `materialize` itself
    /// reports `RetryRequired` for exactly this case) would silently be
    /// marked "done" by this asymmetry -- the DAG projection layer would
    /// never revisit it, so if the sending peer later disappears before a
    /// periodic full-index resend delivers this deletion again, it is lost
    /// for good. Requires a case-insensitive filesystem to raise a real
    /// hazard through the full DAG projection path -- see this module's
    /// own `a_never_seen_tombstone_does_not_leak_wire_metadata_onto_its_
    /// landed_row` for the filesystem-independent half of this same fix.
    #[tokio::test]
    async fn a_hazard_declined_tombstone_reaching_dag_projection_is_not_marked_settled() {
        let h = harness("device-local", "device-p").await;
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&h.root) {
            eprintln!("skipping: {} is case-sensitive here", h.root.display());
            return;
        }

        // "Gone.txt" is live and materialized -- the sibling the tombstone
        // will collide with.
        std::fs::write(h.root.join("Gone.txt"), b"sibling bytes").unwrap();
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Gone.txt".into(),
                    size: b"sibling bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // A bootstrap-only scaffold at "gone.txt" itself -- the shape
        // `apply_locked_record`'s never-seen branch used to leave behind
        // for a hazard-declined tombstone. `still_live` in the `Absent` branch below reads
        // this scaffold's `deleted = 0` as "still live", which is exactly
        // what routes this case through `materialize` rather than the
        // trivial "already absent" fast path.
        yadorilink_daemon::local_convergence::types::apply_incoming_wire_metadata(
            h.state.as_ref(),
            GROUP,
            &FileRecord {
                path: "gone.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_daemon::local_convergence::types::IncomingWireMeta {
                xattrs: Vec::new(),
                record_kind: RecordKind::File,
                symlink_target: None,
                symlink_out_of_root: false,
                unix_mode: None,
                authoring_change_hash: None,
                origin_device_id: None,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

        let key_p = SigningKey::from_bytes(&[4u8; 32]);
        let change_t = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("gone.txt".into()),
            }],
            &key_p,
        );
        h.state.change_history_repository().dag_admit_change(&change_t).unwrap();

        let attempt = h
            .session
            .convergence
            .reconcile_paths_directly(
                &h.session.driver(),
                GROUP,
                std::collections::BTreeSet::from(["gone.txt".to_string()]),
            )
            .await
            .unwrap()
            .expect("audit guard must be free");

        assert!(
            attempt.needs_retry("gone.txt"),
            "a dropped hazard-collision tombstone must be reported as needing retry, not settled: \
             {attempt:?}"
        );
        assert!(
            !attempt.is_settled("gone.txt"),
            "the DAG projection layer must never mark this path resolved while it never actually \
             applied the deletion anywhere"
        );
        assert!(h
            .state
            .materialization_state_repository()
            .get_held_state(GROUP, "gone.txt")
            .unwrap()
            .is_none());
        assert_eq!(
            std::fs::read(h.root.join("Gone.txt")).unwrap(),
            b"sibling bytes",
            "the sibling must remain untouched"
        );
    }

    /// The legacy `apply_locked_record` path had the identical asymmetry
    /// the DAG `Absent` branch above did, but one layer further out: its
    /// never-seen branch called `self.materialize(...).await?` and
    /// discarded the `Ok` value entirely, always returning
    /// `LockedRecordOutcome::Settled` regardless of whether `materialize`
    /// actually reported `Settled` or `RetryRequired`. This is reachable
    /// for non-tombstone records too (an eager fetch that couldn't obtain
    /// every block, a reconstruct failure), not just tombstones -- a
    /// hazard-collision tombstone for a never-seen path is simply the
    /// easiest case to construct directly.
    #[tokio::test]
    async fn apply_locked_record_propagates_retry_required_from_a_dropped_hazard_tombstone() {
        let h = harness("device-local", "device-p").await;
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&h.root) {
            eprintln!("skipping: {} is case-sensitive here", h.root.display());
            return;
        }

        std::fs::write(h.root.join("Gone.txt"), b"sibling bytes").unwrap();
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Gone.txt".into(),
                    size: b"sibling bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(
            h.state.file_index_repository().get_file(GROUP, "gone.txt").unwrap().is_none(),
            "precondition: no prior row at all for the tombstone's own path"
        );

        let key_p = SigningKey::from_bytes(&[5u8; 32]);
        let change_t = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("gone.txt".into()),
            }],
            &key_p,
        );
        h.state.change_history_repository().dag_admit_change(&change_t).unwrap();

        let incoming = FileRecord {
            path: "gone.txt".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let meta = yadorilink_daemon::local_convergence::types::IncomingWireMeta {
            xattrs: Vec::new(),
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: None,
            origin_device_id: None,
            authoring_change_hash: Some(yadorilink_replica_domain::ids::ChangeHash(
                change_t.compute_hash().0,
            )),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let outcome = h
            .session
            .convergence
            .apply_locked_record(&h.session.driver(), GROUP, incoming, meta, policy)
            .await
            .unwrap();

        assert!(
            matches!(
                outcome,
                yadorilink_daemon::local_convergence::types::LockedRecordOutcome::RetryRequired
            ),
            "a dropped hazard-collision tombstone must propagate RetryRequired through the legacy \
             path too, not just the DAG path -- got {outcome:?}"
        );
        assert!(
            h.state.file_index_repository().get_file(GROUP, "gone.txt").unwrap().is_none(),
            "no scaffold left behind either"
        );
    }

    /// The strong version of the authoring-advance fix: unlike
    /// `hazardous_tombstone_materialize_advances_a_differing_authoring_hash`
    /// (which drives `materialize` directly with an arbitrary hash),
    /// this test builds two REAL admitted DAG changes -- a parent
    /// tombstone this device already applied, and a genuinely descendant
    /// tombstone from another device -- and goes in through
    /// `apply_locked_record`, so `dag_compare_authoring` itself proves the
    /// incoming identity is causally newer before the fast path inside
    /// `materialize` ever runs. The direct-unit version alone couldn't
    /// distinguish "advances to a newer identity" from "just overwrites
    /// with whatever's supplied", since `materialize` trusts its caller
    /// for causal ordering rather than checking it itself.
    #[tokio::test]
    async fn redelivery_of_a_real_dag_descendant_tombstone_advances_authoring_identity_through_the_ordering_gate(
    ) {
        let h = harness("device-local", "device-p").await;
        if !yadorilink_peer_session::hazard::is_case_insensitive_filesystem(&h.root) {
            eprintln!("skipping: {} is case-sensitive here", h.root.display());
            return;
        }

        // Written and indexed BEFORE any change is admitted: once a group
        // has any admitted change, `files_require_authoring_identity_on_
        // insert`/`_on_update` require every `current`/`version_seq > 0`
        // row to carry a verified authoring identity, and this sibling's
        // own authoring change is irrelevant to what this test exercises.
        std::fs::write(h.root.join("Photo.jpg"), b"fresh photo bytes").unwrap();
        h.state
            .file_index_repository()
            .upsert_file(
                GROUP,
                &FileRecord {
                    path: "Photo.jpg".into(),
                    size: b"fresh photo bytes".len() as u64,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let key_parent = SigningKey::from_bytes(&[6u8; 32]);
        let parent_change = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-p".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("photo.jpg".into()),
            }],
            &key_parent,
        );
        h.state.change_history_repository().dag_admit_change(&parent_change).unwrap();
        let parent_hash =
            yadorilink_replica_domain::ids::ChangeHash(parent_change.compute_hash().0);
        // This device already applied the parent tombstone: a genuine
        // (version_seq > 0) row stamped with its authoring identity.
        h.state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                GROUP,
                &FileRecord {
                    path: "photo.jpg".into(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: true,
                },
                "device-p",
                &parent_hash,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        // A different device re-tombstones the same path, causally AFTER
        // the parent -- a genuine DAG descendant, not an arbitrary hash.
        let key_descendant = SigningKey::from_bytes(&[8u8; 32]);
        let descendant_change = create_signed_for_tests(
            vec![parent_change.compute_hash()],
            parent_change.lamport,
            yadorilink_replica_domain::ids::DeviceId("device-q".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![yadorilink_replica_domain::change::Op::Delete {
                path: SyncPath("photo.jpg".into()),
            }],
            &key_descendant,
        );
        h.state.change_history_repository().dag_admit_change(&descendant_change).unwrap();
        let descendant_hash =
            yadorilink_replica_domain::ids::ChangeHash(descendant_change.compute_hash().0);

        let incoming = FileRecord {
            path: "photo.jpg".into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: true,
        };
        let meta = yadorilink_daemon::local_convergence::types::IncomingWireMeta {
            xattrs: Vec::new(),
            record_kind: RecordKind::File,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: None,
            origin_device_id: None,
            authoring_change_hash: Some(descendant_hash),
        };
        let yadorilink_replica_domain::session_state::LinkGate::Live { policy, .. } =
            h.state.link_repository().link_gate_for_group(GROUP).unwrap()
        else {
            panic!("link must be live");
        };
        let outcome = h
            .session
            .convergence
            .apply_locked_record(&h.session.driver(), GROUP, incoming, meta, policy)
            .await
            .unwrap();

        assert!(
            matches!(
                outcome,
                yadorilink_daemon::local_convergence::types::LockedRecordOutcome::Settled
            ),
            "this deletion already converged (already a genuine tombstone on both sides) -- got \
             {outcome:?}"
        );
        assert_eq!(
            h.state.file_index_repository().get_authoring_change_hash(GROUP, "photo.jpg").unwrap(),
            Some(descendant_hash),
            "the row's authoring identity must advance to the causally-newer descendant \
             tombstone, proven newer by dag_compare_authoring itself, not stay stuck at the \
             parent's"
        );
        assert!(
            h.state.file_index_repository().get_file(GROUP, "photo.jpg").unwrap().unwrap().deleted,
            "still a clean tombstone"
        );
        assert_eq!(
            std::fs::read(h.root.join("Photo.jpg")).unwrap(),
            b"fresh photo bytes",
            "the sibling must remain untouched"
        );
    }

    /// Regression for the confirmed arrival-order divergence (see
    /// `retire_unjustified_ephemeral_conflict_copies`'s own doc comment): a
    /// conflict copy the projection fixpoint derived while its losing head
    /// was live is a purely local, uncarried artifact. While the loser
    /// stays live the audit must KEEP it (a device that reconciles now
    /// derives the same copy — no divergence, and deleting it would fight
    /// the fixpoint). Once the loser is superseded by its own author's
    /// next edit — closing the conflict window with no cross-branch merge,
    /// so no change ever carries the copy — the audit must retire it,
    /// because a device that first reconciles after the window closed
    /// never derives it, and the two file sets would otherwise disagree
    /// forever under byte-identical DAGs.
    #[tokio::test]
    async fn audit_retires_an_ephemeral_conflict_copy_once_its_loser_window_closes() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[1u8; 32]);
        let key_b = SigningKey::from_bytes(&[2u8; 32]);
        let version_w = empty_version(OLD_MTIME);
        let version_l = empty_version(NEW_MTIME);

        // Two concurrent roots on "shared.bin": winner W (device-a) and
        // loser L (device-b), genuinely different contents.
        let change_w = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_w.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        let change_l = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-b".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_l.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_b,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_w, std::slice::from_ref(&version_w))
            .unwrap();
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_l, std::slice::from_ref(&version_l))
            .unwrap();

        // Reconcile at the transient frontier: the fixpoint derives and
        // materializes the loser's copy locally (ephemeral — no change
        // carries it).
        let (winner_head, loser_head, loser_version) = {
            let heads = h.state.sqlite().dag_group_heads(GROUP).unwrap();
            assert_eq!(heads.len(), 2, "sanity: W and L are concurrent heads");
            if yadorilink_replica_engine::conflict::dag_conflict_loser_is_a(
                change_w.lamport,
                &change_w.compute_hash().0,
                change_l.lamport,
                &change_l.compute_hash().0,
            ) {
                (&change_l, &change_w, &version_w)
            } else {
                (&change_w, &change_l, &version_l)
            }
        };
        let copy_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "shared.bin",
            loser_head.device_id.0.as_str(),
            loser_version.meta.mtime_unix_nanos,
            &loser_version.version_hash.0,
        );
        h.session
            .convergence
            .reconcile_paths_directly(
                &h.session.driver(),
                GROUP,
                std::collections::BTreeSet::from(["shared.bin".into()]),
            )
            .await
            .unwrap()
            .expect("audit guard must be free");
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, &copy_path)
                .unwrap()
                .is_some_and(|r| !r.deleted),
            "precondition: the transient-frontier reconcile derived and indexed the loser's copy \
             at {copy_path:?}"
        );
        assert!(h.root.join(&copy_path).exists(), "precondition: the copy is on disk");

        // While the loser is still live, the audit must NOT retire it.
        crate::drive_materialization_for_test_impl(&h.session, &h.state, GROUP).await.unwrap();
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, &copy_path)
                .unwrap()
                .is_some_and(|r| !r.deleted),
            "a copy still justified by a live loser must survive the audit"
        );

        // The loser's own author supersedes it: the conflict window closes
        // with no cross-branch merge, so no change ever carries the copy.
        let version_l2 = empty_version(NEW_MTIME + 1);
        let loser_child = create_signed_for_tests(
            vec![loser_head.compute_hash()],
            loser_head.lamport,
            loser_head.device_id.clone(),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_l2.version_hash,
                origin: PutOrigin::Direct,
            }],
            if loser_head.device_id.0 == "device-a" { &key_a } else { &key_b },
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&loser_child, std::slice::from_ref(&version_l2))
            .unwrap();
        let _ = winner_head; // winner stays live; only the loser was superseded

        crate::drive_materialization_for_test_impl(&h.session, &h.state, GROUP).await.unwrap();
        assert!(
            !h.root.join(&copy_path).exists(),
            "the no-longer-justified, never-carried copy must be retired from disk"
        );
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, &copy_path)
                .unwrap()
                .is_none_or(|r| r.deleted),
            "the retired copy's index row must not remain live"
        );
    }

    /// Once a conflict-copy path's actual-generation record already
    /// asserts an exact object (as the publication boundary would have
    /// written for it, simulated here directly since this file's harness
    /// never drives `process_group` itself), retiring that copy must
    /// invalidate the record -- `retire_conflict_copies_only`'s own
    /// publication must overwrite it with an `Absent` record under the
    /// frontier it verified. Verified to fail with that publish loop
    /// removed: the stale `RegularFile` record then stays in place after
    /// retirement, failing this test's final assertion.
    #[tokio::test]
    async fn retired_conflict_copy_invalidates_its_actual_generation_record() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[31u8; 32]);
        let key_b = SigningKey::from_bytes(&[32u8; 32]);
        let version_w = empty_version(OLD_MTIME);
        let version_l = empty_version(NEW_MTIME);

        // Two concurrent roots on "shared.bin": winner W (device-a) and
        // loser L (device-b), genuinely different contents -- identical
        // setup to `audit_retires_an_ephemeral_conflict_copy_once_its_
        // loser_window_closes` above.
        let change_w = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_w.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        let change_l = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-b".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_l.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_b,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_w, std::slice::from_ref(&version_w))
            .unwrap();
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_l, std::slice::from_ref(&version_l))
            .unwrap();

        let (loser_head, loser_version) = {
            let heads = h.state.sqlite().dag_group_heads(GROUP).unwrap();
            assert_eq!(heads.len(), 2, "sanity: W and L are concurrent heads");
            if yadorilink_replica_engine::conflict::dag_conflict_loser_is_a(
                change_w.lamport,
                &change_w.compute_hash().0,
                change_l.lamport,
                &change_l.compute_hash().0,
            ) {
                (&change_w, &version_w)
            } else {
                (&change_l, &version_l)
            }
        };
        let copy_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "shared.bin",
            loser_head.device_id.0.as_str(),
            loser_version.meta.mtime_unix_nanos,
            &loser_version.version_hash.0,
        );
        h.session
            .convergence
            .reconcile_paths_directly(
                &h.session.driver(),
                GROUP,
                std::collections::BTreeSet::from(["shared.bin".into()]),
            )
            .await
            .unwrap()
            .expect("audit guard must be free");
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, &copy_path)
                .unwrap()
                .is_some_and(|r| !r.deleted),
            "precondition: the transient-frontier reconcile derived and indexed the loser's copy"
        );

        // Simulate what `process_group`'s own publication boundary would
        // have written for this copy once materialized -- this file's
        // harness never drives `process_group` itself, so the initial
        // exact-object publish is injected directly via the same port
        // method `process_group` calls.
        let frontier_before_retirement = h.state.sqlite().dag_group_heads(GROUP).unwrap();
        let fence_before_retirement =
            h.state.dag_snapshot_mutation_fence(GROUP, &copy_path).unwrap();
        let published = h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                &copy_path,
                &frontier_before_retirement,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    version: loser_version.version_hash,
                    identity: Box::new(None),
                },
                fence_before_retirement,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(published, "sanity: the simulated initial publish must succeed");
        assert!(
            matches!(
                h.state.sqlite().dag_lookup_materialized_generation(GROUP, &copy_path).unwrap(),
                Some(basis) if basis.object_kind
                    == yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile
            ),
            "sanity: the copy's actual-generation record now asserts an exact object"
        );

        // The loser's own author supersedes it: the conflict window closes
        // with no cross-branch merge, so no change ever carries the copy,
        // and the audit must retire it.
        let version_l2 = empty_version(NEW_MTIME + 1);
        let loser_child = create_signed_for_tests(
            vec![loser_head.compute_hash()],
            loser_head.lamport,
            loser_head.device_id.clone(),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_l2.version_hash,
                origin: PutOrigin::Direct,
            }],
            if loser_head.device_id.0 == "device-a" { &key_a } else { &key_b },
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&loser_child, std::slice::from_ref(&version_l2))
            .unwrap();

        let outcome = h.session.convergence.retire_conflict_copies_only(GROUP).await.unwrap();
        assert!(
            matches!(
                outcome,
                yadorilink_daemon::local_convergence::types::RetirementAttempt::Settled { .. }
            ),
            "a stable-frontier retirement pass must settle, got {outcome:?}"
        );
        assert!(
            !h.root.join(&copy_path).exists(),
            "sanity: the no-longer-justified copy must be physically retired"
        );

        let after_retirement =
            h.state.sqlite().dag_lookup_materialized_generation(GROUP, &copy_path).unwrap();
        assert!(
            matches!(
                &after_retirement,
                Some(basis) if basis.object_kind
                    == yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Absent
            ),
            "retirement must invalidate the stale exact-object record and publish Absent under \
             the frontier it verified, got {after_retirement:?}"
        );
    }

    /// A retirement never attributes its deletion to whatever peer the
    /// session that ran it happens to talk to.
    ///
    /// Retirement is decided from local durable state alone, so the peer is
    /// not an input — but the tombstone used to be attributed to
    /// `peer_device_id` anyway, which looked correct only because the daemon's
    /// synthetic local session set that field to this device's own id. Run
    /// through a session with a real, different peer, the old attribution
    /// records that peer as having deleted a file it never saw.
    ///
    /// This no longer even reaches an attribution decision:
    /// `retire_unjustified_ephemeral_conflict_copies` retires a purely local,
    /// non-DAG-backed conflict copy by erasing its index row outright
    /// (`erase_local_only_file`) rather than asserting a tombstone with an
    /// origin — the schema's `files_require_authoring_identity_on_*`
    /// triggers reject a fresh 'current' row with no verified authoring
    /// identity once the group has any DAG history, and there is no DAG
    /// change to attribute this deletion to. So the row is simply gone, with
    /// no origin recorded at all — which trivially also means it is never
    /// misattributed to the peer.
    #[tokio::test]
    async fn a_retirement_erases_the_row_without_attributing_it_to_the_session_peer() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[41u8; 32]);
        let key_b = SigningKey::from_bytes(&[42u8; 32]);
        let version_w = empty_version(OLD_MTIME);
        let version_l = empty_version(NEW_MTIME);

        // Two concurrent roots on "shared.bin": winner W (device-a) and
        // loser L (device-b), genuinely different contents -- identical
        // setup to `audit_retires_an_ephemeral_conflict_copy_once_its_
        // loser_window_closes` above.
        let change_w = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_w.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        let change_l = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-b".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_l.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_b,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_w, std::slice::from_ref(&version_w))
            .unwrap();
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_l, std::slice::from_ref(&version_l))
            .unwrap();

        let (loser_head, loser_version) = {
            let heads = h.state.sqlite().dag_group_heads(GROUP).unwrap();
            assert_eq!(heads.len(), 2, "sanity: W and L are concurrent heads");
            if yadorilink_replica_engine::conflict::dag_conflict_loser_is_a(
                change_w.lamport,
                &change_w.compute_hash().0,
                change_l.lamport,
                &change_l.compute_hash().0,
            ) {
                (&change_w, &version_w)
            } else {
                (&change_l, &version_l)
            }
        };
        let copy_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "shared.bin",
            loser_head.device_id.0.as_str(),
            loser_version.meta.mtime_unix_nanos,
            &loser_version.version_hash.0,
        );
        h.session
            .convergence
            .reconcile_paths_directly(
                &h.session.driver(),
                GROUP,
                std::collections::BTreeSet::from(["shared.bin".into()]),
            )
            .await
            .unwrap()
            .expect("audit guard must be free");
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, &copy_path)
                .unwrap()
                .is_some_and(|r| !r.deleted),
            "precondition: the transient-frontier reconcile derived and indexed the loser's copy"
        );

        // Simulate what `process_group`'s own publication boundary would
        // have written for this copy once materialized -- this file's
        // harness never drives `process_group` itself, so the initial
        // exact-object publish is injected directly via the same port
        // method `process_group` calls.
        let frontier_before_retirement = h.state.sqlite().dag_group_heads(GROUP).unwrap();
        let fence_before_retirement =
            h.state.dag_snapshot_mutation_fence(GROUP, &copy_path).unwrap();
        let published = h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                &copy_path,
                &frontier_before_retirement,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    version: loser_version.version_hash,
                    identity: Box::new(None),
                },
                fence_before_retirement,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(published, "sanity: the simulated initial publish must succeed");
        assert!(
            matches!(
                h.state.sqlite().dag_lookup_materialized_generation(GROUP, &copy_path).unwrap(),
                Some(basis) if basis.object_kind
                    == yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile
            ),
            "sanity: the copy's actual-generation record now asserts an exact object"
        );

        // The loser's own author supersedes it: the conflict window closes
        // with no cross-branch merge, so no change ever carries the copy,
        // and the audit must retire it.
        let version_l2 = empty_version(NEW_MTIME + 1);
        let loser_child = create_signed_for_tests(
            vec![loser_head.compute_hash()],
            loser_head.lamport,
            loser_head.device_id.clone(),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_l2.version_hash,
                origin: PutOrigin::Direct,
            }],
            if loser_head.device_id.0 == "device-a" { &key_a } else { &key_b },
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&loser_child, std::slice::from_ref(&version_l2))
            .unwrap();

        let outcome = h.session.convergence.retire_conflict_copies_only(GROUP).await.unwrap();
        assert!(
            matches!(
                outcome,
                yadorilink_daemon::local_convergence::types::RetirementAttempt::Settled { .. }
            ),
            "a stable-frontier retirement pass must settle, got {outcome:?}"
        );
        assert!(
            !h.root.join(&copy_path).exists(),
            "sanity: the no-longer-justified copy must be physically retired"
        );

        assert!(
            h.state.file_index_repository().get_file(GROUP, &copy_path).unwrap().is_none(),
            "an ephemeral conflict copy's row must be erased outright by retirement, not \
             tombstoned with any attribution"
        );
        let origin =
            h.state.file_index_repository().get_origin_device_id(GROUP, &copy_path).unwrap();
        assert_ne!(
            origin.as_deref(),
            Some("device-p"),
            "the session's peer did not delete this file and must not be recorded as having"
        );
    }

    /// Commit 5's own regression: a DAG admission landing WHILE a
    /// retirement pass is mid-flight must not let that pass's outcome be
    /// treated as `Settled` for the frontier generation it targeted, even
    /// when the mutation the pass made was itself a correct decision for
    /// the frontier it started with. Deterministic, not timing-dependent:
    /// the pass is blocked on the SAME `path_lock` `retire_unjustified_
    /// ephemeral_conflict_copies` acquires right before its own
    /// `materialize` call, held by this test until after the new
    /// admission lands, so there is no race to get unlucky on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn frontier_change_mid_pass_defers_completion_and_a_follow_up_settles_the_new_frontier() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[21u8; 32]);
        let key_b = SigningKey::from_bytes(&[22u8; 32]);
        let version_w = empty_version(OLD_MTIME);

        // A single, uncontested winner for "shared.bin" -- no live loser,
        // so any copy-shaped file under it is unjustified from the start.
        let change_w = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_w.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_w, std::slice::from_ref(&version_w))
            .unwrap();

        let copy_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "shared.bin",
            "device-l",
            NEW_MTIME,
            &[9u8; 32],
        );
        let copy_record = FileRecord {
            path: copy_path.clone(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        };
        h.state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                GROUP,
                &copy_record,
                "device-local",
                &change_w.compute_hash(),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        std::fs::write(h.root.join(&copy_path), b"").unwrap();

        // Simulate the `Present(version=W)` publish the publication
        // boundary would have written for this copy once materialized --
        // same simulation `retired_conflict_copy_
        // invalidates_its_actual_generation_record` uses, since this
        // file's harness never drives `process_group` itself.
        {
            let frontier_now = h.state.sqlite().dag_group_heads(GROUP).unwrap();
            let fence_now = h.state.dag_snapshot_mutation_fence(GROUP, &copy_path).unwrap();
            assert!(
                h.state
                    .dag_publish_materialized_generation_if_fence_current(
                        GROUP,
                        &copy_path,
                        &frontier_now,
                        yadorilink_peer_session::ports::ExactActualState::Object {
                            kind: RecordKind::File,
                            // The version the copy's OWN row names, not
                            // the winner's -- a proof has to be about the
                            // row it describes.
                            version: row_version(&h.state, &copy_path),
                            identity: Box::new(None),
                        },
                        fence_now,
                        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                    )
                    .unwrap(),
                "sanity: the simulated initial publish must succeed"
            );
        }

        // Hold the exact path_lock retirement's own materialize call for
        // `copy_path` will block on -- see `retire_unjustified_ephemeral_
        // conflict_copies`'s own doc comment for why it acquires this
        // before deleting.
        let path_lock = { h.state.path_lock(GROUP, &copy_path) };
        let held = path_lock.lock().await;

        let session = h.session.clone();
        let pass =
            tokio::spawn(
                async move { session.convergence.retire_conflict_copies_only(GROUP).await },
            );

        // Real wall-clock margin for the spawned pass to reach the blocked
        // lock -- it has already read `frontier_before` and determined
        // `copy_path` unjustified by the time it gets there.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // A genuinely new admission lands while the pass is blocked
        // mid-flight, unrelated to "shared.bin" or `copy_path` -- the
        // frontier change alone is what must matter, not what it touches.
        let version_l = empty_version(NEW_MTIME);
        let change_l = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-b".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("other.bin".into()),
                version: version_l.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_b,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_l, std::slice::from_ref(&version_l))
            .unwrap();

        drop(held); // let the blocked pass proceed and finish

        let outcome = pass.await.unwrap().unwrap();
        assert_eq!(
            outcome,
            yadorilink_daemon::local_convergence::types::RetirementAttempt::FrontierChanged,
            "a frontier change while the pass was mid-flight must not be reported as Settled, \
             even though the copy it examined was correctly retired under the frontier it \
             started with"
        );
        // The old-frontier mutation is NOT undone -- it was a correct
        // decision for the frontier that existed while the pass ran.
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, &copy_path)
                .unwrap()
                .is_none_or(|r| r.deleted),
            "the copy was genuinely unjustified under the frontier the pass evaluated it \
             against; FrontierChanged must not roll this back"
        );
        // The deletion is real and stays real (asserted above), but a
        // `FrontierChanged` pass must publish no fresh `Absent` for it --
        // `frontier_before` is no longer provably this group's causal
        // basis. The path's actual-generation record must be left
        // non-usable: not the stale `Present(version=W)` this test
        // published above (its own pre-delete bump already invalidated
        // it), and not a fresh `Absent` either.
        assert_eq!(
            h.state.sqlite().dag_lookup_materialized_generation(GROUP, &copy_path).unwrap(),
            None,
            "a FrontierChanged retirement pass must leave the retired path's record non-usable \
             -- neither the stale Present it started with nor a fresh Absent it has no \
             frontier proof to publish"
        );

        // A follow-up pass against the now-stable frontier must settle
        // cleanly -- this is the "always converge against the CURRENT
        // frontier" half of the guarantee, not just "never lose an event".
        let follow_up = h.session.convergence.retire_conflict_copies_only(GROUP).await.unwrap();
        assert!(
            matches!(
                follow_up,
                yadorilink_daemon::local_convergence::types::RetirementAttempt::Settled { .. }
            ),
            "a follow-up pass against a stable frontier must settle, got {follow_up:?}"
        );
    }

    /// The desired-side hash builder (`desired_resolved_path_state_hash`)
    /// and the real actual-side publication path (`process_group`'s own
    /// boundary, simulated here via the identical port call -- this
    /// file's harness never drives `process_group` itself) must agree
    /// end to end on `resolved_path_state_hash` for the same resolved
    /// content -- not merely individually correct in isolation. The real
    /// risk this guards: `desired_state.rs`'s own `map_record_kind` and
    /// the real `ReplicaCoordinator`'s `RecordKind -> MaterializedObjectKind`
    /// mapping (`yadorilink-daemon/src/replica_coordinator/peer_replica_
    /// state.rs`) are two independently-written mappings that currently
    /// agree but share no code -- nothing enforces they stay in sync.
    /// Verified to fail when the daemon-side
    /// mapping is mismatched (`RecordKind::File -> MaterializedObjectKind::Directory`).
    #[tokio::test]
    async fn ordinary_materialization_publishes_a_hash_that_matches_stage1s_desired_side_builder() {
        let h = harness("device-local", "device-p").await;
        let key = SigningKey::from_bytes(&[41u8; 32]);
        let version = empty_version(OLD_MTIME);
        let change = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("plain.txt".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change, std::slice::from_ref(&version))
            .unwrap();

        let heads_before = h.state.sqlite().dag_group_heads(GROUP).unwrap();

        // The "legacy/ordinary path" materialization -- no worker involved.
        let attempt = h
            .session
            .convergence
            .reconcile_paths_directly(
                &h.session.driver(),
                GROUP,
                std::collections::BTreeSet::from(["plain.txt".into()]),
            )
            .await
            .unwrap()
            .expect("audit guard must be free");

        let (kind, version_hash, identity, mutation_generation) =
            match attempt.evidence_for("plain.txt") {
                Some(
                    yadorilink_daemon::local_convergence::types::SettlementEvidence::ExactObject {
                        kind,
                        version,
                        identity,
                        mutation_generation,
                    },
                ) => (*kind, *version, identity.clone(), *mutation_generation),
                other => panic!("expected plain.txt to settle as ExactObject, got {other:?}"),
            };

        // Simulate process_group's own publication boundary (this harness
        // never drives process_group itself -- same pattern as 3.11/3.15).
        let published = h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                "plain.txt",
                &heads_before,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind,
                    version: version_hash,
                    identity,
                },
                mutation_generation,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(published, "sanity: the simulated publish must land");

        let actual = h
            .state
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "plain.txt")
            .unwrap()
            .expect("row must be published");

        let desired_hash = h
            .state
            .sqlite()
            .dag_desired_resolved_path_state_hash(
                GROUP,
                "plain.txt",
                &yadorilink_replica_engine::conflict::PathResolution::Present {
                    winner: 0,
                    conflict_copies: vec![],
                },
                Some(&version_hash),
            )
            .unwrap();

        assert_eq!(
            actual.resolved_path_state_hash, desired_hash,
            "Stage 1's desired-side hash builder and Stage 3's real actual-side publication path \
             (the real ReplicaCoordinator's RecordKind->MaterializedObjectKind mapping) must \
             produce byte-identical resolved_path_state_hash for the same resolved content"
        );
        assert_eq!(
            actual.object_kind,
            yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile
        );
        assert_eq!(actual.version, Some(version_hash));
    }

    /// A real eager write must leave the DAG-side
    /// `projection_obligations` row untouched -- nothing about
    /// materialize() consults or mutates it directly; only the
    /// DAG-admission seams and the engine's own completion do -- and must
    /// leave no PRIOR proof readable, because its pre-mutation fence bump
    /// invalidates whatever this path carried before.
    ///
    /// This used to model the window between physical success and the
    /// engine's publication, by simply never publishing. That window is
    /// gone: materialize now commits its own proof, under the epoch it
    /// bumped, for the version it wrote. So what this pins is the stronger
    /// shape -- the stale `Absent` proof is not merely unusable, it has
    /// been replaced by a usable one describing what is actually on disk,
    /// and the obligation is still the engine's to close.
    ///
    /// Verified to fail when the real write's pre-mutation
    /// `dag_bump_mutation_fence` call is swapped for a
    /// `dag_snapshot_mutation_fence` (a read-only no-op): a real mutation
    /// whose fence never advanced.
    #[tokio::test]
    async fn a_real_write_leaves_the_projection_obligation_untouched_and_no_prior_proof_readable() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[42u8; 32]);
        let version = empty_version(OLD_MTIME);
        let change = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("crash-path.bin".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change, std::slice::from_ref(&version))
            .unwrap();

        // The real DAG admission seam already bumped projection_obligations
        // for this path to generation 1.
        let obligation_before = h
            .state
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "crash-path.bin")
            .unwrap()
            .expect("admission must have created an obligation");
        assert_eq!(obligation_before.invalidation_generation, 1);

        // Simulate a PRIOR successful publish for this path (what
        // process_group's own boundary would have written on an earlier
        // tick) -- makes the "no usable stale proof" assertion below
        // non-trivial: there IS something to invalidate.
        let fence0 = h.state.dag_snapshot_mutation_fence(GROUP, "crash-path.bin").unwrap();
        assert_eq!(fence0, 0);
        assert!(h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                "crash-path.bin",
                &h.state.sqlite().dag_group_heads(GROUP).unwrap(),
                yadorilink_peer_session::ports::ExactActualState::Absent,
                fence0,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap());
        assert!(
            matches!(
                h.state.sqlite().dag_lookup_materialized_generation(GROUP, "crash-path.bin").unwrap(),
                Some(basis) if basis.object_kind
                    == yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Absent
            ),
            "sanity: the simulated prior publish is usable before the crash-inducing mutation"
        );

        // The real write. It publishes its own proof now, so there is no
        // longer a window here to simulate a crash in -- what is checked
        // below is that the prior `Absent` proof cannot survive it and
        // that the obligation is left alone.
        let head = yadorilink_replica_engine::conflict::PathHead {
            change_hash: change.compute_hash().0,
            lamport: change.lamport,
            device_id: "device-a".into(),
            // Ordinary put: the signer wrote the content, so the carrier and
            // the naming identity are the same device.
            naming_device_id: "device-a".into(),
            content: Some(yadorilink_replica_engine::conflict::PathHeadContent {
                version_hash: version.version_hash.0,
                mtime_unix_nanos: version.meta.mtime_unix_nanos,
            }),
        };
        let result = h
            .session
            .convergence
            .materialize_dag_content_head(
                GROUP,
                "crash-path.bin",
                "crash-path.bin",
                &head,
                yadorilink_replica_domain::session_state::MaterializationPolicy::Eager,
                None,
                None,
            )
            .await
            .unwrap();
        let mutation_generation = match result {
            yadorilink_daemon::local_convergence::types::MaterializeResult::Settled(
                yadorilink_daemon::local_convergence::types::SettlementEvidence::ExactObject {
                    mutation_generation,
                    ..
                },
            ) => mutation_generation,
            other => panic!("expected a real write to settle as ExactObject, got {other:?}"),
        };
        assert_eq!(
            mutation_generation, 1,
            "the real write must have bumped the fence past the prior publish's generation 0"
        );
        assert!(
            h.root.join("crash-path.bin").exists(),
            "sanity: the physical write really happened"
        );

        let obligation_after = h
            .state
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "crash-path.bin")
            .unwrap()
            .unwrap();
        assert_eq!(
            obligation_after.invalidation_generation, obligation_before.invalidation_generation,
            "materialize() must not touch the DAG-side obligation at all -- closing it is the \
             engine's own step"
        );
        let proof = h
            .state
            .sqlite()
            .dag_lookup_materialized_generation(GROUP, "crash-path.bin")
            .unwrap()
            .expect("the write commits its own proof, so one must be readable");
        assert_eq!(
            proof.object_kind,
            yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile,
            "the prior Absent publish must not survive a real write -- it describes a path \
             state that is no longer true"
        );
        assert_eq!(
            proof.version,
            Some(version.version_hash),
            "and the proof must name the version this write actually put on disk"
        );
    }

    /// Replays the exact race with the DAG frontier held constant
    /// throughout. A materialization attempt (M) computes its evidence
    /// for a conflict-copy path (fence bumped, NOT yet published); before
    /// M's publication runs, an independent retirement pass judges the
    /// same copy unjustified, bumps its fence again, and physically
    /// deletes it -- publishing its own `Absent` under a fresh epoch.
    /// M's late publication must then be rejected by the
    /// mutation-generation CAS, and the path's actual-side state must
    /// still reflect retirement's outcome, not M's stale `Present(L)`.
    /// `outcome == Settled` here is this layer's proxy for "the frontier
    /// guard is observed to pass" (matching `retire_conflict_copies_
    /// only`'s own whole-pass frontier check) -- the literal
    /// `process_group` comparison lives in `yadorilink-daemon` and is out
    /// of scope for this harness, same limitation the sibling tests
    /// above already record. Closing the obligation itself is also outside
    /// this harness. Verified to fail when the fence-equality check is
    /// removed from `publish_materialized_generation_if_fence_current`.
    #[tokio::test]
    async fn old_attempt_cannot_republish_after_later_mutation_under_same_dag_frontier() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[51u8; 32]);
        let key_b = SigningKey::from_bytes(&[52u8; 32]);
        let version_w = empty_version(OLD_MTIME);
        let version_l = empty_version(NEW_MTIME);

        let change_w = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_w.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        let change_l = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-b".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_l.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_b,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_w, std::slice::from_ref(&version_w))
            .unwrap();
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_l, std::slice::from_ref(&version_l))
            .unwrap();

        let (loser_head, loser_version) = {
            let heads = h.state.sqlite().dag_group_heads(GROUP).unwrap();
            assert_eq!(heads.len(), 2, "sanity: W and L are concurrent heads");
            if yadorilink_replica_engine::conflict::dag_conflict_loser_is_a(
                change_w.lamport,
                &change_w.compute_hash().0,
                change_l.lamport,
                &change_l.compute_hash().0,
            ) {
                (&change_w, &version_w)
            } else {
                (&change_l, &version_l)
            }
        };
        let copy_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "shared.bin",
            loser_head.device_id.0.as_str(),
            loser_version.meta.mtime_unix_nanos,
            &loser_version.version_hash.0,
        );
        h.session
            .convergence
            .reconcile_paths_directly(
                &h.session.driver(),
                GROUP,
                std::collections::BTreeSet::from(["shared.bin".into()]),
            )
            .await
            .unwrap()
            .expect("audit guard must be free");
        assert!(
            h.state
                .file_index_repository()
                .get_file(GROUP, &copy_path)
                .unwrap()
                .is_some_and(|r| !r.deleted),
            "precondition: the transient-frontier reconcile derived and indexed the loser's copy"
        );

        // M's real fence commitment for "writing copy_path to Present(L)" --
        // evidence computed, epoch captured, deliberately NOT yet published.
        let stale_epoch =
            h.state.dag_bump_mutation_fence(GROUP, &copy_path, "materialize").unwrap();

        // The loser's own author supersedes it: the conflict window closes,
        // so the copy becomes unjustified.
        let version_l2 = empty_version(NEW_MTIME + 1);
        let loser_child = create_signed_for_tests(
            vec![loser_head.compute_hash()],
            loser_head.lamport,
            loser_head.device_id.clone(),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_l2.version_hash,
                origin: PutOrigin::Direct,
            }],
            if loser_head.device_id.0 == "device-a" { &key_a } else { &key_b },
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&loser_child, std::slice::from_ref(&version_l2))
            .unwrap();

        // The independent mutator: a real retirement pass. Internally this
        // bumps copy_path's fence again (past stale_epoch), physically
        // deletes it, and -- since nothing else touches the frontier during
        // the pass -- publishes Absent under its own fresh epoch.
        let outcome = h.session.convergence.retire_conflict_copies_only(GROUP).await.unwrap();
        assert_eq!(
            outcome,
            yadorilink_daemon::local_convergence::types::RetirementAttempt::Settled { retired: 1 },
            "this is this layer's proxy for \"the frontier guard is observed to pass\" -- the \
             test proves nothing if the frontier moved during the pass"
        );
        assert!(
            matches!(
                h.state.sqlite().dag_lookup_materialized_generation(GROUP, &copy_path).unwrap(),
                Some(basis) if basis.object_kind
                    == yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Absent
            ),
            "sanity: retirement's own publish must have succeeded before M's late publish runs"
        );

        // M's late publication, using its now-stale epoch.
        let frontier_before = h.state.sqlite().dag_group_heads(GROUP).unwrap();
        let late_published = h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                &copy_path,
                &frontier_before,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    version: version_l.version_hash,
                    identity: Box::new(None),
                },
                stale_epoch,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        assert!(
            !late_published,
            "a stale publication must be rejected by the mutation-generation CAS"
        );
        assert!(
            matches!(
                h.state.sqlite().dag_lookup_materialized_generation(GROUP, &copy_path).unwrap(),
                Some(basis) if basis.object_kind
                    == yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Absent
            ),
            "C's actual-side state must still reflect retirement's outcome, not the stale \
             Present(L)"
        );
    }

    /// The symmetric half of the kind/version guard: `Absent` names no
    /// version, so a version-only guard skipped it entirely.
    ///
    /// A DAG-side recreation moves the row without moving the mutation
    /// fence, so an attempt that legitimately proved absence earlier can
    /// still win the fence CAS afterwards and publish an exact `Absent`
    /// proof over a path that is live again. Nothing downstream
    /// re-derives the truth from the `files` row: the exact completion
    /// compares the proof's hash and the obligation's generation, not
    /// whether the path is really a tombstone.
    #[tokio::test]
    async fn a_stale_absent_publish_is_refused_once_the_row_is_live_again() {
        let h = harness("device-local", "device-p").await;
        let path = "came-back.bin";
        let frontier = h.state.sqlite().dag_group_heads(GROUP).unwrap();

        // An attempt that genuinely observed absence takes its epoch.
        let absent_epoch = h.state.dag_bump_mutation_fence(GROUP, path, "retire").unwrap();

        // With no row at all, absence is the truth and the publish lands.
        assert!(h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                path,
                &frontier,
                yadorilink_peer_session::ports::ExactActualState::Absent,
                absent_epoch,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap());

        // A DAG-side recreation. It does not touch the mutation fence --
        // that is the whole point, and why the fence CAS cannot see it.
        h.state
            .file_index_repository()
            .upsert_file_with_origin(
                GROUP,
                &FileRecord {
                    path: path.to_string(),
                    size: 0,
                    mtime_unix_nanos: NEW_MTIME,
                    blocks: vec![],
                    deleted: false,
                },
                "device-local",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        assert!(
            !h.state
                .dag_publish_materialized_generation_if_fence_current(
                    GROUP,
                    path,
                    &frontier,
                    yadorilink_peer_session::ports::ExactActualState::Absent,
                    absent_epoch,
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap(),
            "the fence has not moved, so only the row can say this path is not absent any more \
             -- and it does"
        );

        // The shape the production bug actually produced: a live,
        // non-deleted row carrying a `held_reason`, which is what
        // `hold_record` leaves behind. A hold is the opposite of an
        // absence -- the path is present in the index and deliberately
        // not written -- and claiming exact absence for it let the
        // engine's EXACT completion close the obligation, since that
        // completion compares the proof's hash and the obligation's
        // generation and never asks the row whether the path is a
        // tombstone.
        h.state
            .materialization_state_repository()
            .set_held(GROUP, path, "case_collision", 0)
            .unwrap();
        assert!(
            !h.state
                .dag_publish_materialized_generation_if_fence_current(
                    GROUP,
                    path,
                    &frontier,
                    yadorilink_peer_session::ports::ExactActualState::Absent,
                    absent_epoch,
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap(),
            "a held path is present and withheld, not absent"
        );

        // And a genuine tombstone still publishes, so the refusals above
        // are about the row being live rather than about `Absent` having
        // become unpublishable.
        h.state
            .file_index_repository()
            .upsert_file_with_origin(
                GROUP,
                &FileRecord {
                    path: path.to_string(),
                    size: 0,
                    mtime_unix_nanos: NEW_MTIME,
                    blocks: vec![],
                    deleted: true,
                },
                "device-local",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert!(h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                path,
                &frontier,
                yadorilink_peer_session::ports::ExactActualState::Absent,
                absent_epoch,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap());
    }

    /// The raw publication entry point must refuse evidence that names
    /// the right version but the wrong KIND.
    ///
    /// `ExactActualState::Object` carries `kind` and `version` as
    /// independent fields, so a guard that checked only the version would
    /// accept `{kind: Symlink, version: <a File's version>}` and write a
    /// durable proof describing an object no `FileVersion` could ever be
    /// -- `version_hash` is a hash over `record_kind` among other things,
    /// so the two halves contradict each other by construction.
    ///
    /// No production producer builds those two halves separately today.
    /// That is the argument for closing this while it is still true.
    #[tokio::test]
    async fn a_publish_whose_kind_disagrees_with_the_row_is_refused() {
        let h = harness("device-local", "device-p").await;
        let path = "wrong-kind.bin";
        let version = empty_version(NEW_MTIME);
        h.state
            .file_index_repository()
            .upsert_file_with_origin(
                GROUP,
                &FileRecord {
                    path: path.to_string(),
                    size: version.size,
                    mtime_unix_nanos: version.meta.mtime_unix_nanos,
                    blocks: vec![],
                    deleted: false,
                },
                "device-local",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let live_version = row_version(&h.state, path);
        let frontier = h.state.sqlite().dag_group_heads(GROUP).unwrap();
        let fence = h.state.dag_bump_mutation_fence(GROUP, path, "wrong_kind_test").unwrap();

        assert!(
            !h.state
                .dag_publish_materialized_generation_if_fence_current(
                    GROUP,
                    path,
                    &frontier,
                    yadorilink_peer_session::ports::ExactActualState::Object {
                        // The row is a File.
                        kind: RecordKind::Symlink,
                        version: live_version,
                        identity: Box::new(None),
                    },
                    fence,
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap(),
            "a proof may not describe this path as a symlink while the row it names is a file"
        );
        assert!(
            h.state.sqlite().dag_lookup_materialized_generation(GROUP, path).unwrap().is_none(),
            "and nothing may be written when it is refused"
        );

        // The same publish with the kind the row actually has is accepted
        // -- so the refusal above is about the kind, not about the
        // fixture being unable to publish at all.
        assert!(h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                path,
                &frontier,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    version: live_version,
                    identity: Box::new(None),
                },
                fence,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap());
    }

    /// Symmetric companion to the test above: a late retirement `Absent`
    /// publication must not overwrite a materialization that
    /// legitimately recreated the path afterwards. Pure fence/CAS-ordering
    /// property -- no DAG admissions needed. Verified to fail under the
    /// same fault as the primary test above.
    #[tokio::test]
    async fn late_retirement_absent_publication_cannot_overwrite_a_path_materialization_recreated()
    {
        let h = harness("device-local", "device-p").await;
        let path = "recreated.bin";

        // Retirement's pre-delete bump -- evidence: Absent, not published yet.
        let retire_epoch = h.state.dag_bump_mutation_fence(GROUP, path, "retire").unwrap();

        // An independent, later materialization legitimately recreates the
        // path. A real one commits the row as well as publishing the
        // proof, and the publish is refused without it -- evidence must
        // be about a version the row actually names.
        let mat_epoch = h.state.dag_bump_mutation_fence(GROUP, path, "materialize").unwrap();
        let frontier = h.state.sqlite().dag_group_heads(GROUP).unwrap();
        let recreated = empty_version(NEW_MTIME);
        h.state
            .file_index_repository()
            .upsert_file_with_origin(
                GROUP,
                &FileRecord {
                    path: path.to_string(),
                    size: recreated.size,
                    mtime_unix_nanos: recreated.meta.mtime_unix_nanos,
                    blocks: vec![],
                    deleted: false,
                },
                "device-local",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        let recreated_version = row_version(&h.state, path);
        assert!(h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                path,
                &frontier,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    version: recreated_version,
                    identity: Box::new(None),
                },
                mat_epoch,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap());

        // Retirement's own late publish, using its now-stale epoch.
        let late_absent = h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                path,
                &frontier,
                yadorilink_peer_session::ports::ExactActualState::Absent,
                retire_epoch,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        assert!(
            !late_absent,
            "a late retirement Absent publish must not overwrite a legitimate later recreation"
        );
        assert!(matches!(
            h.state.sqlite().dag_lookup_materialized_generation(GROUP, path).unwrap(),
            Some(basis) if basis.object_kind
                == yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::RegularFile
                && basis.version == Some(recreated_version)
        ));
    }

    /// A retirement pass with two copy-shaped candidates deletes copy A
    /// cleanly and fails on copy B (a real `Err`, not a hazard -- see
    /// below), so the pass returns `RetryRequired`. A's actual-side
    /// record must still be corrected (`Present(L)` -> `Absent`); B's
    /// record must be untouched; the pass must not complete its
    /// retirement generation (`RetirementAttempt::RetryRequired`, which
    /// `yadorilink-daemon`'s `engine_wrapper::settles_generation` already
    /// keys generation-completion on -- asserting the variant here closes
    /// this sub-claim by composition, no daemon-layer wiring needed).
    ///
    /// B's failure mechanism: a real filename hazard cannot be produced
    /// in this harness (`hazard_reason_for` is hardcoded to
    /// `NamePolicy::Posix` on this platform, where `invalid_name_reason`
    /// is always `None`, and the case-fold/normalization hazards are
    /// gated on live filesystem probes that read false on this project's
    /// actual Linux/ext4 test environment) -- confirmed by reading
    /// `hazard.rs` directly. Instead, B lives under `sub/` and a regular
    /// FILE occupies `sub` on disk while B's index row says `deleted:
    /// false`; `materialize`'s tombstone branch's `std::fs::remove_file`
    /// then fails with `Err(NotADirectory)` (never `NotFound`),
    /// deterministically and platform/privilege-independently (a
    /// read-only parent would not fail for root), propagating as a genuine
    /// `Err` from `materialize()`. (A directory standing at B's own path
    /// no longer errors: a File row's tombstone keeps it and settles
    /// `Retained` -- see
    /// `retirement_keeps_a_directory_standing_at_a_file_row_copy_path`.)
    /// This injects an `Err` from `materialize` (the alternative to an
    /// injected `MaterializeResult::RetryRequired`). Verified to fail when
    /// the publish loop in `retire_conflict_copies_only` is gated on
    /// `matches!(outcome, RetirementAttempt::Settled { .. })` (a
    /// status-keyed implementation).
    #[tokio::test]
    async fn partially_successful_retirement_pass_still_corrects_the_copies_it_deleted() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[61u8; 32]);
        let version_w = empty_version(OLD_MTIME);
        let change_w = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_w.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_w, std::slice::from_ref(&version_w))
            .unwrap();

        let copy_path_a = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "shared.bin",
            "device-l1",
            NEW_MTIME,
            &[9u8; 32],
        );
        let copy_path_b = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "sub/shared.bin",
            "device-l2",
            NEW_MTIME,
            &[10u8; 32],
        );

        for p in [&copy_path_a, &copy_path_b] {
            h.state
                .file_index_repository()
                .upsert_file_with_origin_and_author(
                    GROUP,
                    &FileRecord {
                        path: p.clone(),
                        size: 0,
                        mtime_unix_nanos: 0,
                        blocks: vec![],
                        deleted: false,
                    },
                    "device-local",
                    &change_w.compute_hash(),
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .unwrap();
        }
        std::fs::write(h.root.join(&copy_path_a), b"").unwrap();
        assert!(copy_path_b.starts_with("sub/"), "{copy_path_b}");
        std::fs::write(h.root.join("sub"), b"not a directory").unwrap();

        // Simulate process_group's own prior publish for A only (task
        // 3.11's pattern), so the test can observe Present(L) -> Absent
        // for A specifically.
        let frontier0 = h.state.dag_group_heads(GROUP).unwrap();
        let fence_a0 = h.state.dag_snapshot_mutation_fence(GROUP, &copy_path_a).unwrap();
        assert!(h
            .state
            .dag_publish_materialized_generation_if_fence_current(
                GROUP,
                &copy_path_a,
                &frontier0,
                yadorilink_peer_session::ports::ExactActualState::Object {
                    kind: RecordKind::File,
                    // A's own row, not the winner's version -- see
                    // `row_version`.
                    version: row_version(&h.state, &copy_path_a),
                    identity: Box::new(None),
                },
                fence_a0,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap());
        // B gets NO pre-existing publish -- must stay None throughout.
        assert_eq!(
            h.state.sqlite().dag_lookup_materialized_generation(GROUP, &copy_path_b).unwrap(),
            None
        );

        let outcome = h.session.convergence.retire_conflict_copies_only(GROUP).await.unwrap();
        assert_eq!(
            outcome,
            yadorilink_daemon::local_convergence::types::RetirementAttempt::RetryRequired,
            "B's Err must make the whole pass RetryRequired, not Settled -- this IS \"does not \
             complete its retirement generation\" (engine_wrapper::settles_generation is keyed \
             on this variant alone)"
        );

        // A really was deleted, both on disk and in the index.
        assert!(!h.root.join(&copy_path_a).exists());
        assert!(h
            .state
            .file_index_repository()
            .get_file(GROUP, &copy_path_a)
            .unwrap()
            .is_none_or(|r| r.deleted));

        // A's actual-generation record was corrected: Present(L) -> Absent.
        assert!(matches!(
            h.state.sqlite().dag_lookup_materialized_generation(GROUP, &copy_path_a).unwrap(),
            Some(basis) if basis.object_kind
                == yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind::Absent
        ));

        // B is untouched: its obstruction is still on disk, still a live
        // index row, still no published record at all.
        assert!(h.root.join("sub").is_file());
        assert!(h
            .state
            .file_index_repository()
            .get_file(GROUP, &copy_path_b)
            .unwrap()
            .is_some_and(|r| !r.deleted));
        assert_eq!(
            h.state.sqlite().dag_lookup_materialized_generation(GROUP, &copy_path_b).unwrap(),
            None
        );
    }

    /// First-class directories (D4=A): YadoriLink never deletes content it
    /// does not track. A DIRECTORY standing where an unjustified conflict
    /// copy's File row was is not the copy -- nothing captured it -- so the
    /// retirement pass keeps it on disk, settles (no retry churn), erases
    /// the copy's row, records the directory as retained, and publishes no
    /// `Absent` proof for a path that is not absent.
    #[tokio::test]
    async fn retirement_keeps_a_directory_standing_at_a_file_row_copy_path() {
        let h = harness("device-local", "device-p").await;
        let key_a = SigningKey::from_bytes(&[62u8; 32]);
        let version_w = empty_version(OLD_MTIME);
        let change_w = create_signed_for_tests(
            vec![],
            0,
            yadorilink_replica_domain::ids::DeviceId("device-a".into()),
            yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            vec![Op::Put {
                path: SyncPath("shared.bin".into()),
                version: version_w.version_hash,
                origin: PutOrigin::Direct,
            }],
            &key_a,
        );
        h.state
            .change_history_repository()
            .dag_admit_change_with_versions(&change_w, std::slice::from_ref(&version_w))
            .unwrap();

        let copy_path = yadorilink_replica_engine::conflict::conflict_copy_path_for_losing_change(
            "shared.bin",
            "device-l1",
            NEW_MTIME,
            &[11u8; 32],
        );
        h.state
            .file_index_repository()
            .upsert_file_with_origin_and_author(
                GROUP,
                &FileRecord {
                    path: copy_path.clone(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: vec![],
                    deleted: false,
                },
                "device-local",
                &change_w.compute_hash(),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        std::fs::create_dir(h.root.join(&copy_path)).unwrap();

        let outcome = h.session.convergence.retire_conflict_copies_only(GROUP).await.unwrap();
        assert!(
            matches!(
                outcome,
                yadorilink_daemon::local_convergence::types::RetirementAttempt::Settled { .. }
            ),
            "a kept directory is a settled outcome, not a retry: {outcome:?}"
        );

        assert!(h.root.join(&copy_path).is_dir(), "an uncaptured directory must never be deleted");
        assert!(h
            .state
            .file_index_repository()
            .get_file(GROUP, &copy_path)
            .unwrap()
            .is_none_or(|r| r.deleted));
        assert!(
            h.state.sqlite().retained_directory_reason(GROUP, &copy_path).unwrap().is_some(),
            "the kept directory is recorded as retained"
        );
        assert_eq!(
            h.state.sqlite().dag_lookup_materialized_generation(GROUP, &copy_path).unwrap(),
            None,
            "no Absent proof for a path a directory still occupies"
        );
    }

    // ---- CORE: DAG-decided winner is order-independent and the gate keeps the
    // legacy mtime path from overriding it. ----

    struct MultiAuthenticator {
        keys: HashMap<String, [u8; 32]>,
    }
    impl ChangeAuthenticator for MultiAuthenticator {
        fn resolve_authority_key(
            &self,
            _group_id: &str,
            signer_key_id: &[u8; 32],
            _policy_head: &[u8; 32],
        ) -> Option<ed25519_dalek::VerifyingKey> {
            self.keys.values().find_map(|bytes| {
                let key =
                    yadorilink_replica_domain::change::verifying_key_from_bytes(bytes).ok()?;
                (&yadorilink_replica_domain::authorization_checkpoint::fingerprint_signing_key(
                    &key,
                ) == signer_key_id)
                    .then_some(key)
            })
        }
    }

    fn empty_version(mtime: i64) -> FileVersion {
        FileVersion::new(
            vec![],
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

    fn create_op(path: &str, version: &FileVersion) -> Op {
        Op::Put {
            path: SyncPath(path.into()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        }
    }

    /// Two genuinely concurrent Create-`file.bin` changes with mtime INVERTED
    /// against lamport: device-a's change carries the higher lamport (a warm-up
    /// change raises its clock) but the OLDER mtime, device-b's carries the
    /// lower lamport but the NEWER mtime. The DAG winner is therefore device-a
    /// (higher lamport) while the mtime resolver would pick device-b.
    fn concurrent_changes() -> (Change, Change, Change, FileVersion, FileVersion, FileVersion) {
        let key_a = SigningKey::from_bytes(&[7u8; 32]);
        let key_b = SigningKey::from_bytes(&[8u8; 32]);
        let warm_v = empty_version(500);
        let va = empty_version(OLD_MTIME);
        let vb = empty_version(NEW_MTIME);

        let conn_a = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&conn_a).unwrap();
        dag_store::put_file_version(&conn_a, GROUP, &warm_v).unwrap();
        dag_store::put_file_version(&conn_a, GROUP, &va).unwrap();
        let emitter_a = ChangeEmitter::new("device-a", key_a);
        let warm = dag_store::emit_local_change(
            &conn_a,
            GROUP,
            vec![create_op("warmup.txt", &warm_v)],
            &emitter_a,
        )
        .unwrap();
        let change_a = dag_store::emit_local_change(
            &conn_a,
            GROUP,
            vec![create_op("file.bin", &va)],
            &emitter_a,
        )
        .unwrap();

        let conn_b = rusqlite::Connection::open_in_memory().unwrap();
        dag_store::init_dag_schema(&conn_b).unwrap();
        dag_store::put_file_version(&conn_b, GROUP, &vb).unwrap();
        let emitter_b = ChangeEmitter::new("device-b", key_b);
        let change_b = dag_store::emit_local_change(
            &conn_b,
            GROUP,
            vec![create_op("file.bin", &vb)],
            &emitter_b,
        )
        .unwrap();

        assert!(
            change_a.lamport > change_b.lamport,
            "test setup: device-a's change must carry the higher lamport ({} vs {})",
            change_a.lamport,
            change_b.lamport
        );
        (warm, change_a, change_b, warm_v, va, vb)
    }
}
