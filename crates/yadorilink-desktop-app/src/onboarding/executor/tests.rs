#![cfg(test)]

use super::*;

#[test]
fn register_ok_maps_to_device_registered() {
    assert_eq!(register_to_event(Ok("dev-1".into())), Event::DeviceRegistered);
}

#[test]
fn register_err_carries_the_message() {
    let ev = register_to_event(Err(CoreError::NotLoggedIn));
    match ev {
        Event::DeviceRegisterFailed(msg) => assert!(msg.contains("not logged in")),
        other => panic!("expected DeviceRegisterFailed, got {other:?}"),
    }
}

#[test]
fn create_and_link_ok_carries_group_id() {
    assert_eq!(
        create_and_link_to_event(Ok("g-42".into())),
        Event::CreateAndLinkSucceeded { group_id: "g-42".into() }
    );
}

#[test]
fn list_groups_ok_maps_each_summary() {
    let groups = vec![
        share::GroupSummary { group_id: "g1".into(), name: "Photos".into() },
        share::GroupSummary { group_id: "g2".into(), name: "Docs".into() },
    ];
    assert_eq!(
        list_groups_to_event(Ok(groups)),
        Event::GroupsListed(vec![
            GroupOption { group_id: "g1".into(), name: "Photos".into() },
            GroupOption { group_id: "g2".into(), name: "Docs".into() },
        ])
    );
}

#[test]
fn link_ok_maps_to_link_succeeded() {
    assert_eq!(link_to_event(Ok(())), Event::LinkSucceeded);
}

/// The report→view conversion carries every warning through verbatim
/// (the window's acknowledgement cards are exactly the CLI's warnings)
/// and reflects the report's own risk verdict.
#[test]
fn preflight_view_carries_warnings_and_risk_from_a_real_report() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("existing.txt"), b"x").unwrap();
    // Some(0) disables the free-space headroom check so this test's verdict
    // is driven purely by the non-empty-folder condition, not the host's
    // disk state.
    let report = yadorilink_local_storage::link_preflight::run_preflight(dir.path(), &[], Some(0));
    let view = preflight_to_view(dir.path().to_path_buf(), &report);

    assert!(view.is_risky);
    assert_eq!(view.warnings, report.warnings());
    assert!(view.warnings.iter().any(|w| w.contains("not empty")));
    assert!(view.summary.iter().any(|s| s.contains("non-empty folder")));
    assert_eq!(view.resolved_path, dir.path().to_string_lossy());
}

#[test]
fn preflight_view_of_an_empty_folder_has_no_non_empty_warning() {
    let dir = tempfile::tempdir().unwrap();
    let report = yadorilink_local_storage::link_preflight::run_preflight(dir.path(), &[], Some(0));
    let view = preflight_to_view(dir.path().to_path_buf(), &report);
    assert!(!view.warnings.iter().any(|w| w.contains("not empty")));
    assert!(view.summary.iter().any(|s| s.contains("empty folder")));
}
