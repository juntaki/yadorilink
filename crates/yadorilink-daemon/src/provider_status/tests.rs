use super::*;
use yadorilink_replica_domain::session_state::ProviderKind;

fn root() -> ProviderRoot {
    ProviderRoot {
        root_id: "abcdef0123456789".into(),
        group_id: "g".into(),
        kind: ProviderKind::MacFileProvider,
        display_name: "Photos".into(),
        domain_registered: false,
        first_handshake_at: None,
        error_description: None,
        namespace_ready: false,
        latest_evidence_seq: 0,
    }
}

/// Each state of a root's readiness has its own words; first run says "enable File Provider".
#[test]
fn readiness_reasons_read_as_what_to_do() {
    let mut r = root();
    assert_eq!(readiness_text(&r), "waiting for the app to register the folder");
    r.domain_registered = true;
    assert_eq!(readiness_text(&r), "enable File Provider");
    r.first_handshake_at = Some(1);
    assert_eq!(readiness_text(&r), "preparing the folder");
    r.namespace_ready = true;
    assert_eq!(readiness_text(&r), "ready");
    r.error_description = Some("disk full".into());
    assert_eq!(readiness_text(&r), "File Provider error: disk full");
}

/// The control socket sees nothing until the shell side installs the builder, then what it builds.
#[test]
fn the_status_source_is_empty_until_installed() {
    let source = ProviderStatusSource::default();
    assert!(source.snapshot().is_empty());
    source.install(Arc::new(|| {
        vec![ProviderRootStatus { display_name: "Photos".into(), ..Default::default() }]
    }));
    assert_eq!(source.snapshot()[0].display_name, "Photos");
}

#[test]
fn eager_progress_and_stuck_files_are_encoded() {
    let mut line = ProviderRootStatus::default();
    encode_eager(
        &EagerStatus {
            state: DriverState::PausedLowDisk,
            remote: 5,
            hydrating: 2,
            current: 9,
            stuck: vec![("a/b.bin".into(), 4)],
        },
        &mut line,
    );
    assert!(line.eager);
    assert_eq!(
        (line.eager_state.as_str(), line.eager_remote, line.eager_hydrating, line.eager_current),
        ("paused (low disk)", 5, 2, 9)
    );
    assert_eq!((line.stuck[0].path.as_str(), line.stuck[0].failures), ("a/b.bin", 4));
}

/// The rollup flags a provider folder that needs the user: not ready, stuck files, kept edits.
#[test]
fn the_overall_status_names_provider_folders_that_need_attention() {
    let response = yadorilink_ipc_proto::daemonctl::StatusResponse {
        provider_roots: vec![
            ProviderRootStatus {
                root_id: "r1".into(),
                readiness: "enable File Provider".into(),
                ..Default::default()
            },
            ProviderRootStatus {
                root_id: "r2".into(),
                readiness: "ready".into(),
                stuck: vec![StuckFile { path: "x".into(), failures: 3 }],
                kept_edits: 1,
                ..Default::default()
            },
            ProviderRootStatus {
                root_id: "r3".into(),
                readiness: "ready".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let reasons = crate::control_socket::attention_reasons_for_tests(&response);
    assert!(reasons.contains(&"provider_not_ready:r1".to_owned()), "{reasons:?}");
    assert!(reasons.contains(&"provider_stuck:r2".to_owned()));
    assert!(reasons.contains(&"kept_edits:r2".to_owned()));
    assert!(!reasons.iter().any(|r| r.ends_with(":r3")));
}
