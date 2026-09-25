#![cfg(test)]

use super::*;
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;

#[test]
fn records_are_bounded_and_return_newest_first() {
    let log = ConnectionTraceLog::new();
    for i in 0..(MAX_TRACE_ENTRIES + 10) {
        log.record(
            format!("device-{i}"),
            CandidateSource::CoordinationPlane,
            AddressClass::Wan,
            AttemptOutcome::Connected,
            10,
            "",
            true,
            Some(true),
        );
    }
    let recent = log.recent(None);
    assert_eq!(recent.len(), MAX_TRACE_ENTRIES);
    // Newest first: the very last one recorded is device-(N+9).
    assert_eq!(recent[0].peer_device_id, format!("device-{}", MAX_TRACE_ENTRIES + 9));
}

#[test]
fn filters_by_peer_device_id() {
    let log = ConnectionTraceLog::new();
    log.record(
        "device-a",
        CandidateSource::CoordinationPlane,
        AddressClass::Wan,
        AttemptOutcome::Connected,
        5,
        "",
        true,
        Some(true),
    );
    log.record(
        "device-b",
        CandidateSource::CoordinationPlane,
        AddressClass::Unknown,
        AttemptOutcome::Failed,
        0,
        "no_response",
        false,
        None,
    );
    let filtered = log.recent(Some("device-a"));
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].peer_device_id, "device-a");
}

#[test]
fn never_carries_a_raw_address_field() {
    // Structural guarantee, not a runtime one: `ConnectionAttemptTrace`
    // has no field that could hold a raw socket address at all — this
    // test exists to force a compile error (via an exhaustive match
    // with named bindings) if a future edit ever adds one without
    // updating this note.
    let trace = ConnectionAttemptTrace {
        peer_device_id: "device-a".into(),
        candidate_source: "direct",
        address_class: "wan",
        outcome: "connected",
        latency_ms: 1,
        failure_category: String::new(),
        selected: true,
        authorization_decision: "authorized",
        recorded_at_unix_nanos: 0,
    };
    let ConnectionAttemptTrace {
        peer_device_id: _,
        candidate_source: _,
        address_class: _,
        outcome: _,
        latency_ms: _,
        failure_category: _,
        selected: _,
        authorization_decision: _,
        recorded_at_unix_nanos: _,
    } = trace;
}

fn telemetry() -> RuntimeTelemetry {
    RuntimeTelemetry::new(tokio::sync::broadcast::channel(1).0)
}

fn category<'a>(out: &'a [DoctorCategory], name: &str) -> &'a DoctorCategory {
    out.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("no {name} category"))
}

fn find_category<'a>(out: &'a [DoctorCategory], name: &str) -> Option<&'a DoctorCategory> {
    out.iter().find(|c| c.name == name)
}

// --- peer_reachability: sustained per-peer failure must surface ---------

#[test]
fn peer_reachability_warns_after_sustained_failures_with_no_recent_connection() {
    let sync_state = crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
    let telem = telemetry();

    for _ in 0..PEER_UNREACHABLE_MIN_ATTEMPTS {
        telem.record_connection_attempt(
            "device-B",
            CandidateSource::CoordinationPlane,
            AddressClass::Unknown,
            AttemptOutcome::Failed,
            0,
            "no_response",
            false,
            None,
        );
    }

    let out = run_connectivity_doctor(&telem, &sync_state, "device-A");
    let cat = category(&out, "peer_reachability");
    assert_eq!(cat.status, "warn");
    assert!(cat.detail.contains("device-B"), "{cat:?}");
    assert!(cat.detail.contains("no_response"), "{cat:?}");
}

#[test]
fn peer_reachability_is_silent_below_the_sustained_failure_threshold() {
    let sync_state = crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
    let telem = telemetry();

    for _ in 0..(PEER_UNREACHABLE_MIN_ATTEMPTS - 1) {
        telem.record_connection_attempt(
            "device-B",
            CandidateSource::CoordinationPlane,
            AddressClass::Unknown,
            AttemptOutcome::Failed,
            0,
            "no_response",
            false,
            None,
        );
    }

    let out = run_connectivity_doctor(&telem, &sync_state, "device-A");
    assert!(
        find_category(&out, "peer_reachability").is_none(),
        "a single transient retry must not be reported as sustained failure"
    );
}

#[test]
fn peer_reachability_is_silent_once_the_peer_has_reconnected() {
    let sync_state = crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
    let telem = telemetry();

    for _ in 0..PEER_UNREACHABLE_MIN_ATTEMPTS {
        telem.record_connection_attempt(
            "device-B",
            CandidateSource::CoordinationPlane,
            AddressClass::Unknown,
            AttemptOutcome::Failed,
            0,
            "no_response",
            false,
            None,
        );
    }
    // A later, successful reconnection -- this peer is fine now,
    // regardless of the failures that came before it.
    telem.record_connection_attempt(
        "device-B",
        CandidateSource::CoordinationPlane,
        AddressClass::Wan,
        AttemptOutcome::Connected,
        10,
        "",
        true,
        Some(true),
    );

    let out = run_connectivity_doctor(&telem, &sync_state, "device-A");
    assert!(
        find_category(&out, "peer_reachability").is_none(),
        "a peer that has since reconnected must not still be reported as unreachable"
    );
}

#[test]
fn checkpoint_pending_is_ok_when_nothing_is_locally_pending() {
    let sync_state = crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
    let telem = telemetry();

    let out = run_connectivity_doctor(&telem, &sync_state, "device-A");
    assert_eq!(category(&out, "checkpoint_pending").status, "ok");
}

#[test]
fn checkpoint_pending_warns_for_an_unpublished_locally_authored_change_and_clears_once_published() {
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
    use yadorilink_sync_sqlite::dag_store::{
        admit_change, published_view::attach_authorization_evidence,
    };

    let sync_state = crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
    sync_state.link_repository().add_link("/tmp/does-not-matter", "g").unwrap();

    let change = create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-A".into()),
        FolderGroupId("g".into()),
        vec![],
        &SigningKey::from_bytes(&[3u8; 32]),
    );
    sync_state.database().write(|conn| admit_change(conn, &change)).unwrap();

    let telem = telemetry();
    let before = run_connectivity_doctor(&telem, &sync_state, "device-A");
    let before_cat = category(&before, "checkpoint_pending");
    assert_eq!(before_cat.status, "warn");
    assert!(
        before_cat.detail.contains('1'),
        "detail should mention the pending count: {before_cat:?}"
    );

    sync_state
        .database()
        .write(|conn| {
            attach_authorization_evidence(
                conn,
                &[7u8; 32],
                "g",
                "device-A",
                1,
                b"cp",
                b"sig",
                &[0xAAu8; 32],
                &[(change.compute_hash(), b"proof".to_vec())],
            )
        })
        .unwrap();

    let after = run_connectivity_doctor(&telem, &sync_state, "device-A");
    assert_eq!(category(&after, "checkpoint_pending").status, "ok");
}

#[test]
fn checkpoint_pending_ignores_another_devices_pending_change() {
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
    use yadorilink_sync_sqlite::dag_store::admit_change;

    let sync_state = crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
    sync_state.link_repository().add_link("/tmp/does-not-matter", "g").unwrap();

    let others_change = create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-B".into()),
        FolderGroupId("g".into()),
        vec![],
        &SigningKey::from_bytes(&[4u8; 32]),
    );
    sync_state.database().write(|conn| admit_change(conn, &others_change)).unwrap();

    let telem = telemetry();
    let out = run_connectivity_doctor(&telem, &sync_state, "device-A");
    assert_eq!(
        category(&out, "checkpoint_pending").status,
        "ok",
        "device-B's pending change must not count against device-A's own doctor reading"
    );
}
