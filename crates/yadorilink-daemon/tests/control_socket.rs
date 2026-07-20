//! Exercises the CLI ↔ daemon control protocol
//! end-to-end over a real Unix domain socket, without needing a live
//! coordination plane — link/unlink/pause/resume/status/shutdown
//! only ever talk to the local daemon. Wrapped in `#[cfg(unix)]`
//! (Windows local IPC support) — see `shell_ipc.rs`'s test file for why.
#[cfg(unix)]
mod unix_socket_tests {

    use std::sync::Arc;

    use tokio::net::UnixStream;
    use yadorilink_daemon::daemon_state::DaemonState;
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{
        DaemonControlRequest, DaemonControlResponse, EvictRequest, HydrateRequest, LinkRequest,
        ListLinksRequest, ListTrashRequest, ListVersionsRequest, PauseRequest,
        PendingEnrollmentKind, PinRequest, RestoreTrashRequest, RestoreVersionRequest,
        ResumeRequest, StatusRequest, UnlinkRequest, UnpinRequest,
    };
    use yadorilink_ipc_proto::framing::{read_message, write_message};
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::index::SyncState;

    async fn start_daemon() -> (std::path::PathBuf, tempfile::TempDir) {
        let (socket_path, dir, _state) = start_daemon_with_state().await;
        (socket_path, dir)
    }

    /// Like `start_daemon`, but also returns the `DaemonState` handle for
    /// tests that need to index files directly (bypassing the watcher
    /// pipeline, which is covered by `local_change`/`link_manager`'s own tests).
    async fn start_daemon_with_state() -> (std::path::PathBuf, tempfile::TempDir, Arc<DaemonState>)
    {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(dir.path().join("blocks")).unwrap());
        let state_db = Arc::new(SyncState::open(dir.path().join("sync.sqlite3")).unwrap());
        let state = DaemonState::new("device-under-test".into(), state_db, store);
        // A registered (non-empty device_id) device with no change-signing
        // key is fail-closed (`link_manager::ensure_initial_change_history`):
        // linking a folder refuses index-only sync rather than leave
        // emission silently off. Wire one before any test here links.
        state
            .set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);
        let socket_path = dir.path().join("daemon.sock");

        let serve_path = socket_path.clone();
        let serve_state = state.clone();
        tokio::spawn(async move {
            let _ =
                yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_state)
                    .await;
        });

        // Give the listener a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        (socket_path, dir, state)
    }

    async fn send(socket_path: &std::path::Path, payload: ReqPayload) -> DaemonControlResponse {
        let mut stream = UnixStream::connect(socket_path).await.unwrap();
        write_message(
            &mut stream,
            &DaemonControlRequest {
                payload: Some(payload),
                protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap()
    }

    /// cli spec: "Link a folder via CLI" / "List linked folders".
    #[tokio::test]
    async fn link_then_list_shows_it() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("photos");
        std::fs::create_dir_all(&folder).unwrap();

        let resp = send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-1".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Link(_))));

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 1);
        assert_eq!(list.links[0].group_id, "group-1");
        assert!(!list.links[0].paused);
    }

    /// The daemon rejects linking a folder that overlaps an already-linked
    /// folder unless `acknowledge_risks` is set -- defense-in-depth
    /// independent of whatever the CLI already showed/gated, since the
    /// daemon alone knows every existing link's path.
    #[tokio::test]
    async fn link_rejects_unacknowledged_nested_conflict() {
        let (socket_path, dir) = start_daemon().await;
        let parent = dir.path().join("parent");
        let child = parent.join("child");
        std::fs::create_dir_all(&child).unwrap();

        let resp = send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: parent.to_string_lossy().to_string(),
                group_id: "group-1".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Link(_))));

        // Linking `child` (nested inside the already-linked `parent`)
        // without acknowledging the risk is rejected.
        let resp = send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: child.to_string_lossy().to_string(),
                group_id: "group-2".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: false,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        let Some(RespPayload::Error(msg)) = resp.payload else {
            panic!("expected the nested-link conflict to be rejected, got {:?}", resp.payload)
        };
        assert!(msg.contains("nested-link conflict"), "expected a clear message, got {msg:?}");

        // The rejected link never got registered.
        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 1);
    }

    /// The same nested-conflict attempt succeeds once `acknowledge_risks`
    /// is set -- the daemon-side check is a gate, not an absolute ban.
    #[tokio::test]
    async fn link_allows_acknowledged_nested_conflict() {
        let (socket_path, dir) = start_daemon().await;
        let parent = dir.path().join("parent");
        let child = parent.join("child");
        std::fs::create_dir_all(&child).unwrap();

        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: parent.to_string_lossy().to_string(),
                group_id: "group-1".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let resp = send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: child.to_string_lossy().to_string(),
                group_id: "group-2".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Link(_))));

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 2);
    }

    /// sync-engine spec: "Pause halts sync activity" / "Resume processes
    /// queued changes" — exercised at the control-protocol level.
    #[tokio::test]
    async fn pause_then_resume_round_trips_through_status() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-2".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let local_path = folder.to_string_lossy().to_string();
        let resp =
            send(&socket_path, ReqPayload::Pause(PauseRequest { local_path: local_path.clone() }))
                .await;
        assert!(matches!(resp.payload, Some(RespPayload::Pause(_))));

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert!(status.links[0].paused);

        let resp = send(&socket_path, ReqPayload::Resume(ResumeRequest { local_path })).await;
        assert!(matches!(resp.payload, Some(RespPayload::Resume(_))));

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert!(!status.links[0].paused);
    }

    /// cli spec: unlinking removes the folder from subsequent listings.
    #[tokio::test]
    async fn unlink_removes_the_link() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("videos");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-3".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        // An eager link makes this device a full replica of the group, but
        // the linked folder is empty -- nothing to hand off, so the
        // durability gate (`ensure_unlink_keeps_a_full_replica`) is
        // vacuously satisfied regardless of any other recorded peer.
        state.set_peer_group_full_replica("device-b", "group-3", true);

        let resp =
            send(&socket_path, ReqPayload::Unlink(UnlinkRequest { local_path, force: false }))
                .await;
        assert!(matches!(resp.payload, Some(RespPayload::Unlink(_))));

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert!(list.links.is_empty());
    }

    /// THE C14 SEAM, end to end over the real socket.
    ///
    /// A folder group linked at more than one folder refuses to sync entirely.
    /// That refusal is otherwise only a log line -- loud in the code, silent
    /// where the user actually looks -- so status is what makes it visible, and
    /// the paths it names ARE the remedy, since unlinking is keyed by path.
    ///
    /// Drives `ListLinks` over the socket rather than calling the status builder
    /// directly: the producer of this flag was deletable (hardcode `false` ->
    /// "292 passed; 0 failed") precisely because nothing exercised the wiring.
    #[tokio::test]
    async fn status_reports_a_twice_linked_group_as_ambiguous_and_names_both_folders() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder_a = dir.path().join("aaa-photos");
        let folder_b = dir.path().join("bbb-photos");
        std::fs::create_dir_all(&folder_a).unwrap();
        std::fs::create_dir_all(&folder_b).unwrap();

        state.sync_state.add_link(&folder_a.to_string_lossy(), "group-amb").unwrap();
        state
            .sync_state
            .force_second_live_link_for_test(&folder_b.to_string_lossy(), "group-amb")
            .unwrap();

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant: {:?}", resp.payload)
        };

        for link in &list.links {
            assert!(
                link.ambiguous,
                "a folder group linked at two folders must report as not syncing; otherwise the \
                 refusal is invisible to the user and their folder silently stops syncing"
            );
            let mut named = link.ambiguous_local_paths.clone();
            named.sort();
            assert_eq!(
                named,
                vec![
                    folder_a.to_string_lossy().to_string(),
                    folder_b.to_string_lossy().to_string()
                ],
                "status must name every folder involved -- the paths are the remedy"
            );
        }
        assert_eq!(list.links.len(), 2, "both rows must stay visible for recovery");
    }

    /// A healthy one-folder group must NOT be flagged. Without this, hardcoding
    /// `ambiguous: true` would pass the test above and every user would be told
    /// their folders are broken.
    #[tokio::test]
    async fn status_does_not_flag_a_normally_linked_group_as_ambiguous() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("photos");
        std::fs::create_dir_all(&folder).unwrap();
        state.sync_state.add_link(&folder.to_string_lossy(), "group-ok").unwrap();

        let resp = send(&socket_path, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 1);
        assert!(!list.links[0].ambiguous, "a group with one folder is not ambiguous");
        assert_eq!(list.links[0].ambiguous_local_paths.len(), 1);
    }

    /// THE UNLINK-RECOVERY SEAM, end to end over the real socket.
    ///
    /// Unlinking one of two roots is the documented recovery, and the handler
    /// must arm the survivor's additive-scan window as part of it: the departed
    /// root's rows stay in the group's index, and the survivor's next scan is
    /// root-scoped and authoritative, so without the flag the remedy deletes the
    /// files it was meant to save.
    ///
    /// Drives the real `Unlink` request: the `arm_additive_scan_for_survivor`
    /// call was deletable at "292 passed; 0 failed" because the only test that
    /// covered this behaviour set the flag by hand and never asked whether
    /// anything in production sets it.
    #[tokio::test]
    async fn unlinking_one_of_two_roots_arms_the_survivors_additive_scan() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder_a = dir.path().join("aaa-photos");
        let folder_b = dir.path().join("bbb-photos");
        std::fs::create_dir_all(&folder_a).unwrap();
        std::fs::create_dir_all(&folder_b).unwrap();

        state.sync_state.add_link(&folder_a.to_string_lossy(), "group-amb").unwrap();
        state
            .sync_state
            .force_second_live_link_for_test(&folder_b.to_string_lossy(), "group-amb")
            .unwrap();
        state.set_peer_group_full_replica("device-b", "group-amb", true);

        // The window starts closed (the column defaults to 0) and nothing in
        // this test opens it, so a pass below means the unlink handler did. It
        // cannot be asserted here directly: while the group is still ambiguous,
        // reading the flag correctly hits the ambiguity gate. The
        // `an_ordinary_unlink_does_not_arm_any_additive_scan` case is what pins
        // that this is not simply armed unconditionally.
        let resp = send(
            &socket_path,
            ReqPayload::Unlink(UnlinkRequest {
                local_path: folder_b.to_string_lossy().to_string(),
                force: false,
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Unlink(_))), "got {:?}", resp.payload);

        assert!(
            state.sync_state.suppress_tombstones_for_group("group-amb").unwrap(),
            "unlinking one of two roots must make the survivor's next scan additive -- otherwise \
             the recovery this error message instructs deletes every file that only existed in \
             the folder the user unlinked, on every device"
        );
    }

    /// An ordinary unlink -- one folder, one group -- must NOT arm the window.
    /// Arming it unconditionally would suppress the next scan's deletions on a
    /// perfectly healthy link, so a real user deletion made while the daemon was
    /// off would never propagate.
    #[tokio::test]
    async fn an_ordinary_unlink_does_not_arm_any_additive_scan() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder_a = dir.path().join("aaa-photos");
        let folder_b = dir.path().join("bbb-photos");
        std::fs::create_dir_all(&folder_a).unwrap();
        std::fs::create_dir_all(&folder_b).unwrap();

        // Two links, but on DIFFERENT groups: nothing ambiguous here.
        state.sync_state.add_link(&folder_a.to_string_lossy(), "group-x").unwrap();
        state.sync_state.add_link(&folder_b.to_string_lossy(), "group-y").unwrap();
        state.set_peer_group_full_replica("device-b", "group-y", true);

        send(
            &socket_path,
            ReqPayload::Unlink(UnlinkRequest {
                local_path: folder_b.to_string_lossy().to_string(),
                force: false,
            }),
        )
        .await;

        assert!(
            !state.sync_state.suppress_tombstones_for_group("group-x").unwrap(),
            "an unrelated group's link must keep propagating deletions normally"
        );
    }

    /// cli spec: "Status reports per-folder state" — including a live
    /// conflict count derived from the actual index, not just link metadata.
    #[tokio::test]
    async fn status_reports_conflict_count_from_index() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-4".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].conflict_count, 0);
    }

    /// A held file (a cross-platform name hazard, held rather than
    /// materialized or auto-renamed) is surfaced over the control socket
    /// with its count, path, reason, and hold timestamp, sourced from
    /// section 1's
    /// `held_reason`/`held_since_unix_nanos` columns via
    /// `SyncState::set_held`/`get_held_state`.
    #[tokio::test]
    async fn status_reports_held_file_count_and_reason() {
        use yadorilink_sync_core::types::FileRecord;
        use yadorilink_sync_core::version_vector::VersionVector;

        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-held".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let record = FileRecord {
            path: "a.txt".into(),
            size: 3,
            mtime_unix_nanos: 0,
            version: VersionVector::new(),
            blocks: vec![],
            deleted: false,
        };
        state.sync_state.upsert_file("group-held", &record).unwrap();
        state
            .sync_state
            .set_held(
                "group-held",
                "a.txt",
                "case-fold collision with existing sibling 'A.txt'",
                123,
            )
            .unwrap();

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].held_file_count, 1);
        assert_eq!(status.links[0].held_files.len(), 1);
        assert_eq!(status.links[0].held_files[0].path, "a.txt");
        assert_eq!(
            status.links[0].held_files[0].reason,
            "case-fold collision with existing sibling 'A.txt'"
        );
        assert_eq!(status.links[0].held_files[0].held_since_unix_nanos, 123);
    }

    /// An unheld, non-symlink file never contributes to
    /// `held_file_count`/`held_files` — the field is
    /// absent (zero/empty), not merely unpopulated, when nothing in the
    /// link is actually held.
    #[tokio::test]
    async fn status_reports_no_held_files_when_none_are_held() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-not-held".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].held_file_count, 0);
        assert!(status.links[0].held_files.is_empty());
        assert_eq!(status.links[0].skipped_symlink_count, 0);
    }

    /// A symlink record with the Windows default-skip-with-visible-status
    /// policy in effect (`windows_symlink_opt_in` left at its default
    /// `false`) counts toward `skipped_symlink_count` when the daemon
    /// itself is running
    /// on Windows, the only platform where a symlink record is ever left
    /// unmaterialized by policy. **Not exercised on this development
    /// machine** (macOS/Linux only, matching section 3.2's own
    /// already-documented limitation) — this runs for real on this
    /// repository's `windows-latest` CI leg (see `.github/workflows/ci.yml`'s
    /// matrix), which is the first real verification of this `#[cfg(windows)]`
    /// path; reviewed carefully against `control_socket.rs`'s
    /// `is_skipped_windows_symlink` but not hand-run locally.
    #[cfg(windows)]
    #[tokio::test]
    async fn status_reports_skipped_windows_symlink_count() {
        use yadorilink_sync_core::types::{FileRecord, RecordKind};
        use yadorilink_sync_core::version_vector::VersionVector;

        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-symlink".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let record = FileRecord {
            path: "link-to-elsewhere".into(),
            size: 0,
            mtime_unix_nanos: 0,
            version: VersionVector::new(),
            blocks: vec![],
            deleted: false,
        };
        state.sync_state.upsert_file("group-symlink", &record).unwrap();
        state
            .sync_state
            .set_record_kind("group-symlink", "link-to-elsewhere", RecordKind::Symlink)
            .unwrap();
        state
            .sync_state
            .set_symlink_target("group-symlink", "link-to-elsewhere", Some("target.txt"))
            .unwrap();
        // `windows_symlink_opt_in` is left at its default `false` — the
        // default-skip policy this test exercises.

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].skipped_symlink_count, 1);
    }

    /// Same setup as `status_reports_skipped_windows_symlink_count`, but a
    /// Per-link opt-in takes the symlink out of the
    /// default-skip policy — it no longer counts as skipped, since a real
    /// materialization attempt (success or failure) is made instead of a
    /// policy-driven skip. Windows-only for the same reason as its sibling
    /// test above.
    #[cfg(windows)]
    #[tokio::test]
    async fn status_does_not_count_an_opted_in_windows_symlink_as_skipped() {
        use yadorilink_sync_core::types::{FileRecord, RecordKind};
        use yadorilink_sync_core::version_vector::VersionVector;

        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-symlink-optin".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        state.sync_state.set_windows_symlink_opt_in(&local_path, true).unwrap();

        let record = FileRecord {
            path: "link-to-elsewhere".into(),
            size: 0,
            mtime_unix_nanos: 0,
            version: VersionVector::new(),
            blocks: vec![],
            deleted: false,
        };
        state.sync_state.upsert_file("group-symlink-optin", &record).unwrap();
        state
            .sync_state
            .set_record_kind("group-symlink-optin", "link-to-elsewhere", RecordKind::Symlink)
            .unwrap();
        state
            .sync_state
            .set_symlink_target("group-symlink-optin", "link-to-elsewhere", Some("target.txt"))
            .unwrap();

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].skipped_symlink_count, 0);
    }

    /// Cross-platform counterpart to `status_reports_skipped_windows_symlink_count`,
    /// runnable on this development machine: on a non-Windows daemon, a
    /// symlink record is never counted as policy-skipped, since only the
    /// Windows default-skip branch of `is_skipped_windows_symlink` ever
    /// returns `true` — a symlink materializes normally via
    /// `chunker::materialize_symlink` on every POSIX peer, regardless of
    /// `windows_symlink_opt_in`.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn status_reports_zero_skipped_symlinks_on_non_windows_even_for_a_symlink_record() {
        use yadorilink_sync_core::types::{FileRecord, RecordKind};
        use yadorilink_sync_core::version_vector::VersionVector;

        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-symlink-posix".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let record = FileRecord {
            path: "link-to-elsewhere".into(),
            size: 0,
            mtime_unix_nanos: 0,
            version: VersionVector::new(),
            blocks: vec![],
            deleted: false,
        };
        state.sync_state.upsert_file("group-symlink-posix", &record).unwrap();
        state
            .sync_state
            .set_record_kind("group-symlink-posix", "link-to-elsewhere", RecordKind::Symlink)
            .unwrap();
        state
            .sync_state
            .set_symlink_target("group-symlink-posix", "link-to-elsewhere", Some("target.txt"))
            .unwrap();

        let resp = send(&socket_path, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(status.links[0].skipped_symlink_count, 0);
    }

    /// manual eviction round-trips through the
    /// control socket: a hydrated file becomes a placeholder, its sync state
    /// (blocks) untouched.
    #[tokio::test]
    async fn evict_via_control_socket_turns_a_hydrated_file_into_a_placeholder() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-5".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        // No index entry exists for this path (the watcher pipeline that
        // would create one is exercised elsewhere, e.g. `local_change`'s and
        // `link_manager`'s own tests) — eviction over the control socket must
        // report a clear error rather than silently no-op'ing on an unknown path.
        let resp = send(
            &socket_path,
            ReqPayload::Evict(EvictRequest {
                absolute_path: folder.join("report.pdf").to_string_lossy().to_string(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Error(_))));
    }

    /// evicting a genuinely-indexed, hydrated
    /// file turns it into a correctly-sized placeholder, over the control
    /// socket end to end.
    #[tokio::test]
    async fn evict_via_control_socket_succeeds_for_an_indexed_hydrated_file() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path,
                group_id: "group-7".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let content = vec![7u8; 1000];
        std::fs::write(folder.join("report.pdf"), &content).unwrap();
        let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
        version.increment("device-a");
        state
            .sync_state
            .upsert_file(
                "group-7",
                &yadorilink_sync_core::types::FileRecord {
                    path: "report.pdf".into(),
                    size: 1000,
                    mtime_unix_nanos: 0,
                    version,
                    blocks: vec![yadorilink_sync_core::types::BlockInfo {
                        hash: vec![0xEFu8; 32],
                        offset: 0,
                        size: 1000,
                    }],
                    deleted: false,
                },
            )
            .unwrap();

        let resp = send(
            &socket_path,
            ReqPayload::Evict(EvictRequest {
                absolute_path: folder.join("report.pdf").to_string_lossy().to_string(),
            }),
        )
        .await;
        assert!(
            matches!(resp.payload, Some(RespPayload::Evict(_))),
            "indexed hydrated file should evict successfully, got {:?}",
            resp.payload
        );

        assert_eq!(
            state.sync_state.get_materialization_state("group-7", "report.pdf").unwrap(),
            Some(yadorilink_sync_core::types::MaterializationState::Placeholder)
        );
        let metadata = std::fs::metadata(folder.join("report.pdf")).unwrap();
        assert_eq!(metadata.len(), 1000);
        assert_ne!(std::fs::read(folder.join("report.pdf")).unwrap(), content);
    }

    /// hydrate/pin with no peer connected must
    /// return a clear error over the control socket, not hang the connection.
    #[tokio::test]
    async fn hydrate_and_pin_without_a_connected_peer_return_a_clear_error() {
        let (socket_path, dir) = start_daemon().await;
        let folder = dir.path().join("shared");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path,
                group_id: "group-6".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let nope_path = folder.join("nope.bin").to_string_lossy().to_string();

        let resp = send(
            &socket_path,
            ReqPayload::Hydrate(HydrateRequest { absolute_path: nope_path.clone() }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Error(_))));

        let resp =
            send(&socket_path, ReqPayload::Pin(PinRequest { absolute_path: nope_path.clone() }))
                .await;
        assert!(matches!(resp.payload, Some(RespPayload::Error(_))));

        // Unpin needs no peer at all, but still requires the path to actually
        // be indexed — same "not found" error as any other unknown path.
        let resp =
            send(&socket_path, ReqPayload::Unpin(UnpinRequest { absolute_path: nope_path })).await;
        assert!(matches!(resp.payload, Some(RespPayload::Error(_))));
    }
    /// `ListVersions`/`RestoreVersion` round-trip against a running
    /// daemon — an edit produces a superseded version, `versions` lists
    /// both (newest first, including current), and restoring the
    /// superseded version writes its content back to disk as a brand-new
    /// current version (never rewrites history).
    #[tokio::test]
    async fn list_versions_then_restore_version_round_trips_through_control_socket() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path,
                group_id: "group-versions".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let v1_hash = state.block_store.put(b"version one").unwrap();
        let v1_block = yadorilink_sync_core::types::BlockInfo {
            hash: hex::decode(&v1_hash).unwrap(),
            offset: 0,
            size: 11,
        };
        // Mirrors what `LocalChangeProcessor` does for a real local edit
        // (`record_group_block_provenance`'s doc comment): without this, a
        // restore treats a block this test poked directly into the store as
        // never having been obtained through the group, and refuses it.
        state
            .sync_state
            .record_group_block_provenance("group-versions", &[v1_block.hash.clone()])
            .unwrap();
        let mut v1_version = yadorilink_sync_core::version_vector::VersionVector::new();
        v1_version.increment("device-a");
        state
            .sync_state
            .upsert_file_with_origin(
                "group-versions",
                &yadorilink_sync_core::types::FileRecord {
                    path: "notes.txt".into(),
                    size: 11,
                    mtime_unix_nanos: 1,
                    version: v1_version,
                    blocks: vec![v1_block.clone()],
                    deleted: false,
                },
                "device-a",
            )
            .unwrap();

        let v2_hash = state.block_store.put(b"version two!").unwrap();
        let v2_block = yadorilink_sync_core::types::BlockInfo {
            hash: hex::decode(&v2_hash).unwrap(),
            offset: 0,
            size: 12,
        };
        state
            .sync_state
            .record_group_block_provenance("group-versions", &[v2_block.hash.clone()])
            .unwrap();
        let mut v2_version = yadorilink_sync_core::version_vector::VersionVector::new();
        v2_version.increment("device-a");
        v2_version.increment("device-a");
        state
            .sync_state
            .upsert_file_with_origin(
                "group-versions",
                &yadorilink_sync_core::types::FileRecord {
                    path: "notes.txt".into(),
                    size: 12,
                    mtime_unix_nanos: 2,
                    version: v2_version,
                    blocks: vec![v2_block],
                    deleted: false,
                },
                "device-a",
            )
            .unwrap();

        let absolute_path = folder.join("notes.txt").to_string_lossy().to_string();
        let resp = send(
            &socket_path,
            ReqPayload::ListVersions(ListVersionsRequest { absolute_path: absolute_path.clone() }),
        )
        .await;
        let Some(RespPayload::ListVersions(list)) = resp.payload else {
            panic!("wrong response variant: {resp:?}")
        };
        assert_eq!(list.versions.len(), 2, "both versions must be listed, including current");
        assert_eq!(list.versions[0].version_seq, 2, "newest first");
        assert_eq!(list.versions[0].state, "current");
        assert_eq!(list.versions[0].origin_device_id, "device-a");
        assert_eq!(list.versions[1].version_seq, 1);
        assert_eq!(list.versions[1].state, "superseded");

        let resp = send(
            &socket_path,
            ReqPayload::RestoreVersion(RestoreVersionRequest {
                absolute_path: absolute_path.clone(),
                version_seq: Some(1),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::RestoreVersion(_))), "{resp:?}");

        assert_eq!(std::fs::read(folder.join("notes.txt")).unwrap(), b"version one");
        let versions = state.sync_state.list_versions("group-versions", "notes.txt").unwrap();
        assert_eq!(versions.len(), 3, "restore must add a new version, not rewrite history");
        assert_eq!(versions[0].version_seq, 3);
        assert_eq!(versions[0].blocks, vec![v1_block]);
    }

    /// `RestoreVersion` with no `version_seq` defaults to the most
    /// recent superseded version (spec "Restore without a version defaults
    /// to the most recent superseded version").
    #[tokio::test]
    async fn restore_version_without_a_version_seq_defaults_to_most_recent_superseded() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path,
                group_id: "group-default-restore".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let v1_hash = state.block_store.put(b"first").unwrap();
        let v1_block = yadorilink_sync_core::types::BlockInfo {
            hash: hex::decode(&v1_hash).unwrap(),
            offset: 0,
            size: 5,
        };
        // See the identical comment in `list_versions_then_restore_version_
        // round_trips_through_control_socket` above.
        state
            .sync_state
            .record_group_block_provenance("group-default-restore", &[v1_block.hash.clone()])
            .unwrap();
        let mut v1_version = yadorilink_sync_core::version_vector::VersionVector::new();
        v1_version.increment("device-a");
        state
            .sync_state
            .upsert_file_with_origin(
                "group-default-restore",
                &yadorilink_sync_core::types::FileRecord {
                    path: "todo.txt".into(),
                    size: 5,
                    mtime_unix_nanos: 1,
                    version: v1_version,
                    blocks: vec![v1_block.clone()],
                    deleted: false,
                },
                "device-a",
            )
            .unwrap();

        let v2_hash = hex::decode(state.block_store.put(b"second content").unwrap()).unwrap();
        state
            .sync_state
            .record_group_block_provenance("group-default-restore", &[v2_hash.clone()])
            .unwrap();
        let mut v2_version = yadorilink_sync_core::version_vector::VersionVector::new();
        v2_version.increment("device-a");
        v2_version.increment("device-a");
        state
            .sync_state
            .upsert_file_with_origin(
                "group-default-restore",
                &yadorilink_sync_core::types::FileRecord {
                    path: "todo.txt".into(),
                    size: 14,
                    mtime_unix_nanos: 2,
                    version: v2_version,
                    blocks: vec![yadorilink_sync_core::types::BlockInfo {
                        hash: v2_hash,
                        offset: 0,
                        size: 14,
                    }],
                    deleted: false,
                },
                "device-a",
            )
            .unwrap();

        let absolute_path = folder.join("todo.txt").to_string_lossy().to_string();
        let resp = send(
            &socket_path,
            ReqPayload::RestoreVersion(RestoreVersionRequest {
                absolute_path: absolute_path.clone(),
                version_seq: None,
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::RestoreVersion(_))), "{resp:?}");
        assert_eq!(std::fs::read(folder.join("todo.txt")).unwrap(), b"first");

        // No superseded version at all -> clear error, not a silent no-op.
        let folder2 = dir.path().join("empty");
        std::fs::create_dir_all(&folder2).unwrap();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: folder2.to_string_lossy().to_string(),
                group_id: "group-no-superseded".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        let mut only_version = yadorilink_sync_core::version_vector::VersionVector::new();
        only_version.increment("device-a");
        state
            .sync_state
            .upsert_file_with_origin(
                "group-no-superseded",
                &yadorilink_sync_core::types::FileRecord {
                    path: "solo.txt".into(),
                    size: 0,
                    mtime_unix_nanos: 1,
                    version: only_version,
                    blocks: vec![],
                    deleted: false,
                },
                "device-a",
            )
            .unwrap();
        let resp = send(
            &socket_path,
            ReqPayload::RestoreVersion(RestoreVersionRequest {
                absolute_path: folder2.join("solo.txt").to_string_lossy().to_string(),
                version_seq: None,
            }),
        )
        .await;
        let Some(RespPayload::Error(msg)) = resp.payload else { panic!("expected an error") };
        assert!(msg.contains("superseded"), "expected a clear message, got {msg:?}");
    }

    /// the missing-blocks restore failure path surfaces
    /// `SyncError::VersionContentUnavailable` specifically over IPC, not a
    /// generic error message — `RespPayload::Error` is just `e.to_string`,
    /// so this checks the text actually identifies unavailable version
    /// content (see that variant's `#[error(...)]` text in `error.rs`).
    #[tokio::test]
    async fn restore_version_with_missing_blocks_surfaces_a_distinguishable_error() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path,
                group_id: "group-missing-blocks".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        // A version referencing a block never actually written to this
        // device's block store (as if evicted, or never fetched).
        let phantom_block = yadorilink_sync_core::types::BlockInfo {
            hash: {
                use sha2::{Digest, Sha256};
                Sha256::digest(b"never fetched").to_vec()
            },
            offset: 0,
            size: 13,
        };
        let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
        version.increment("device-a");
        state
            .sync_state
            .upsert_file_with_origin(
                "group-missing-blocks",
                &yadorilink_sync_core::types::FileRecord {
                    path: "phantom.bin".into(),
                    size: 13,
                    mtime_unix_nanos: 1,
                    version,
                    blocks: vec![phantom_block],
                    deleted: false,
                },
                "device-a",
            )
            .unwrap();

        let resp = send(
            &socket_path,
            ReqPayload::RestoreVersion(RestoreVersionRequest {
                absolute_path: folder.join("phantom.bin").to_string_lossy().to_string(),
                version_seq: Some(1),
            }),
        )
        .await;
        let Some(RespPayload::Error(msg)) = resp.payload else {
            panic!("expected an error, got {resp:?}")
        };
        assert!(
            msg.contains("unavailable") && msg.to_lowercase().contains("version"),
            "expected a message identifying unavailable version content, got {msg:?}"
        );
        assert!(!folder.join("phantom.bin").exists(), "a failed restore must not create a file");
    }

    /// `ListTrash`/`RestoreTrash` round-trip — a deleted file
    /// shows up in `trash list`, and `trash restore` recovers it as a new
    /// live current version.
    #[tokio::test]
    async fn list_trash_then_restore_trash_round_trips_through_control_socket() {
        let (socket_path, dir, state) = start_daemon_with_state().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        let local_path = folder.to_string_lossy().to_string();
        send(
            &socket_path,
            ReqPayload::Link(LinkRequest {
                local_path: local_path.clone(),
                group_id: "group-trash".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let hash = state.block_store.put(b"soon deleted").unwrap();
        let block = yadorilink_sync_core::types::BlockInfo {
            hash: hex::decode(&hash).unwrap(),
            offset: 0,
            size: 12,
        };
        // See the identical comment in `list_versions_then_restore_version_
        // round_trips_through_control_socket` above.
        state
            .sync_state
            .record_group_block_provenance("group-trash", &[block.hash.clone()])
            .unwrap();
        let mut version = yadorilink_sync_core::version_vector::VersionVector::new();
        version.increment("device-a");
        state
            .sync_state
            .upsert_file_with_origin(
                "group-trash",
                &yadorilink_sync_core::types::FileRecord {
                    path: "gone.txt".into(),
                    size: 12,
                    mtime_unix_nanos: 1,
                    version,
                    blocks: vec![block],
                    deleted: false,
                },
                "device-a",
            )
            .unwrap();
        state.sync_state.mark_deleted("group-trash", "gone.txt", "device-a").unwrap();

        let resp = send(&socket_path, ReqPayload::ListTrash(ListTrashRequest {})).await;
        let Some(RespPayload::ListTrash(list)) = resp.payload else {
            panic!("wrong response variant: {resp:?}")
        };
        assert_eq!(list.files.len(), 1);
        assert_eq!(list.files[0].local_path, local_path);
        assert_eq!(list.files[0].path, "gone.txt");
        assert_eq!(list.files[0].last_known_size, 12);
        assert_eq!(list.files[0].origin_device_id, "device-a");

        let resp = send(
            &socket_path,
            ReqPayload::RestoreTrash(RestoreTrashRequest {
                absolute_path: folder.join("gone.txt").to_string_lossy().to_string(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::RestoreTrash(_))), "{resp:?}");

        assert_eq!(std::fs::read(folder.join("gone.txt")).unwrap(), b"soon deleted");
        let current = state.sync_state.get_file("group-trash", "gone.txt").unwrap().unwrap();
        assert!(!current.deleted, "the file must be live again after a trash restore");
    }
} // mod unix_socket_tests

/// the same control protocol exercised
/// above over a Unix socket, but over the Windows named-pipe transport —
/// only compiled/run on Windows, where `unix_transport` isn't available at
/// all. Uses a per-test unique pipe name: named pipes live in
/// the `\\.\pipe\` namespace, not the filesystem, so `tempfile::tempdir`
/// isolation doesn't apply the way it does for the Unix-socket tests above.
#[cfg(windows)]
mod windows_pipe_tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use tokio::net::windows::named_pipe::ClientOptions;
    use yadorilink_daemon::daemon_state::DaemonState;
    use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
    use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
    use yadorilink_ipc_proto::daemonctl::{
        DaemonControlRequest, DaemonControlResponse, LinkRequest, ListLinksRequest, PauseRequest,
        ResumeRequest, StatusRequest,
    };
    use yadorilink_ipc_proto::framing::{read_message, write_message};
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::index::SyncState;

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_pipe_name() -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\yadorilink-test-{}-{n}", std::process::id())
    }

    async fn start_daemon() -> (String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(dir.path().join("blocks")).unwrap());
        let state_db = Arc::new(SyncState::open(dir.path().join("sync.sqlite3")).unwrap());
        let state = DaemonState::new("device-under-test".into(), state_db, store);
        // See the identical comment in the Unix `start_daemon_with_state` above.
        state
            .set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);
        let pipe_name = unique_pipe_name();

        let serve_name = pipe_name.clone();
        tokio::spawn(async move {
            let _ = yadorilink_daemon::control_socket::windows_transport::serve(&serve_name, state)
                .await;
        });

        // Give the listener a moment to create the first pipe instance.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        (pipe_name, dir)
    }

    async fn send(pipe_name: &str, payload: ReqPayload) -> DaemonControlResponse {
        let mut stream = ClientOptions::new().open(pipe_name).unwrap();
        write_message(
            &mut stream,
            &DaemonControlRequest {
                payload: Some(payload),
                protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
            },
        )
        .await
        .unwrap();
        read_message::<DaemonControlResponse>(&mut stream).await.unwrap().unwrap()
    }

    #[tokio::test]
    async fn link_then_list_shows_it_over_named_pipe() {
        let (pipe_name, dir) = start_daemon().await;
        let folder = dir.path().join("photos");
        std::fs::create_dir_all(&folder).unwrap();

        let resp = send(
            &pipe_name,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-1".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;
        assert!(matches!(resp.payload, Some(RespPayload::Link(_))));

        let resp = send(&pipe_name, ReqPayload::ListLinks(ListLinksRequest {})).await;
        let Some(RespPayload::ListLinks(list)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert_eq!(list.links.len(), 1);
        assert_eq!(list.links[0].group_id, "group-1");
    }

    /// Confirms the daemon really is serving multiple connections
    /// concurrently over the named pipe (the pre-create-next-instance
    /// pattern), not just one client ever.
    #[tokio::test]
    async fn pause_then_resume_round_trips_over_named_pipe() {
        let (pipe_name, dir) = start_daemon().await;
        let folder = dir.path().join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        send(
            &pipe_name,
            ReqPayload::Link(LinkRequest {
                local_path: folder.to_string_lossy().to_string(),
                group_id: "group-2".into(),
                on_demand: false,
                max_local_size_bytes: None,
                acknowledge_risks: true,
                pending_enrollment_operation_id: String::new(),
                pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                pending_enrollment_device_id: String::new(),
            }),
        )
        .await;

        let local_path = folder.to_string_lossy().to_string();
        let resp =
            send(&pipe_name, ReqPayload::Pause(PauseRequest { local_path: local_path.clone() }))
                .await;
        assert!(matches!(resp.payload, Some(RespPayload::Pause(_))));

        let resp = send(&pipe_name, ReqPayload::Status(StatusRequest {})).await;
        let Some(RespPayload::Status(status)) = resp.payload else {
            panic!("wrong response variant")
        };
        assert!(status.links[0].paused);

        let resp = send(&pipe_name, ReqPayload::Resume(ResumeRequest { local_path })).await;
        assert!(matches!(resp.payload, Some(RespPayload::Resume(_))));
    }

    /// A second, concurrent client connecting while the first is mid-flight
    /// must not be refused — the daemon's next-instance-pre-created pattern
    ///  exists specifically so this works.
    #[tokio::test]
    async fn two_concurrent_clients_are_both_served() {
        let (pipe_name, dir) = start_daemon().await;
        let folder_a = dir.path().join("a");
        let folder_b = dir.path().join("b");
        std::fs::create_dir_all(&folder_a).unwrap();
        std::fs::create_dir_all(&folder_b).unwrap();

        let pipe_a = pipe_name.clone();
        let pipe_b = pipe_name.clone();
        let (resp_a, resp_b) = tokio::join!(
            send(
                &pipe_a,
                ReqPayload::Link(LinkRequest {
                    local_path: folder_a.to_string_lossy().to_string(),
                    group_id: "group-a".into(),
                    on_demand: false,
                    max_local_size_bytes: None,
                    acknowledge_risks: true,
                    pending_enrollment_operation_id: String::new(),
                    pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                    pending_enrollment_device_id: String::new(),
                }),
            ),
            send(
                &pipe_b,
                ReqPayload::Link(LinkRequest {
                    local_path: folder_b.to_string_lossy().to_string(),
                    group_id: "group-b".into(),
                    on_demand: false,
                    max_local_size_bytes: None,
                    acknowledge_risks: true,
                    pending_enrollment_operation_id: String::new(),
                    pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
                    pending_enrollment_device_id: String::new(),
                }),
            ),
        );
        assert!(matches!(resp_a.payload, Some(RespPayload::Link(_))));
        assert!(matches!(resp_b.payload, Some(RespPayload::Link(_))));
    }
}
