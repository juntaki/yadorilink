#![cfg(test)]

use super::*;

/// `YADORILINK_UPDATE_MANIFEST_URL` is a process-global env var —
/// every test in this module that touches it holds this mutex for
/// its whole body, mirroring `daemon_state.rs`'s own
/// `CONFIG_ENV_MUTEX` precedent for `YADORILINK_CONFIG_DIR`.
static MANIFEST_URL_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn manager(config_dir: &Path) -> UpdateManager {
    UpdateManager::new(config_dir, semver::Version::parse("0.1.0").unwrap())
}

/// Update Privacy requirement / spec "Update check uses coarse
/// metadata only": exercises the *real* HTTP request
/// `check_now` sends (via a real local mock server, not just a code
/// inspection) and asserts its query string carries exactly the six
/// documented coarse fields — schema_version, current_version,
/// platform, arch, channel, install_source — and nothing else: no
/// device id, account id, folder path, peer address, key, or token.
#[tokio::test]
async fn update_check_request_sends_only_the_documented_coarse_fields() {
    use std::collections::BTreeSet;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        // The response body doesn't matter for this test -- an
        // invalid/unsigned body just makes `check_now` return an
        // error, which is fine; only the *request* is under test.
        .respond_with(ResponseTemplate::new(200).set_body_string("not a valid manifest"))
        .mount(&server)
        .await;
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", format!("{}/manifest.json", server.uri()));

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path());
    let _ = manager.check_now().await;

    let requests = server.received_requests().await.expect("request recording must be enabled");
    assert_eq!(requests.len(), 1, "expected exactly one manifest fetch");
    let query_keys: BTreeSet<String> =
        requests[0].url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    let expected: BTreeSet<String> =
        ["schema_version", "current_version", "platform", "arch", "channel", "install_source"]
            .into_iter()
            .map(String::from)
            .collect();
    assert_eq!(
        query_keys, expected,
        "update-check request must carry exactly the documented coarse fields and nothing else"
    );

    std::env::remove_var("YADORILINK_UPDATE_MANIFEST_URL");
}

/// Builds a `ReleaseEntry` that matches `mgr`'s own detected platform
/// context (channel/platform/arch/install_source), so `select_applicable`
/// actually considers it, with the given rollout/kill-switch knobs.
fn matching_entry(
    mgr: &UpdateManager,
    version: &str,
    rollout: u8,
    kill_switch: bool,
) -> manifest::ReleaseEntry {
    manifest::ReleaseEntry {
        channel: "beta".into(),
        platform: mgr.platform_info().platform.clone(),
        arch: mgr.platform_info().arch.clone(),
        install_source: mgr.platform_info().install_source.clone(),
        version: version.into(),
        minimum_supported_version: "0.1.0".into(),
        rollout_percentage: rollout,
        kill_switch,
        mandatory: false,
        artifact_url: "https://example.invalid/yadorilink-update".into(),
        artifact_sha256: "0".repeat(64),
        artifact_size: 1024,
        artifact_publisher_identity: String::new(),
        release_notes_url: "https://example.invalid/notes".into(),
    }
}

async fn serve_envelope_and_check(
    envelope_json: String,
    config_dir: &Path,
) -> Result<Applicability, UpdateError> {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(envelope_json))
        .mount(&server)
        .await;
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", format!("{}/manifest.json", server.uri()));
    let mut mgr = manager(config_dir);
    mgr.set_trusted_keys_for_test(manifest::test_support::trusted_keys_hex(
        &manifest::test_support::test_trusted_keys(),
    ));
    let result = mgr.check_now().await;
    std::env::remove_var("YADORILINK_UPDATE_MANIFEST_URL");
    result
}

/// End-to-end: a real `UpdateManager` fetches a real signed manifest
/// envelope from a real local HTTP server and reaches `Available` for
/// a fully-rolled-out release newer than its current version — the
/// same `manifest::verify_and_parse` path a production daemon runs,
/// exercised through `check_now`, not a unit-level call into
/// `select_applicable` alone.
#[tokio::test]
async fn a_running_daemon_discovers_verifies_and_applies_a_signed_manifest() {
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let entry = matching_entry(&mgr, "9.9.9", 100, false);
    let doc = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
        releases: vec![entry],
    };
    let envelope = manifest::test_support::sign_manifest(&doc);
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let result = serve_envelope_and_check(envelope_json, dir.path()).await;
    match result {
        Ok(Applicability::Available { version, .. }) => {
            assert_eq!(version, semver::Version::parse("9.9.9").unwrap());
        }
        other => panic!("expected a verified Available update, got {other:?}"),
    }
}

/// Same end-to-end path, but the entry's rollout hasn't selected this
/// install (0%): `check_now` must report `HeldBack`, not silently
/// install and not error out.
#[tokio::test]
async fn a_running_daemon_holds_back_an_update_outside_its_rollout_percentage() {
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let entry = matching_entry(&mgr, "9.9.9", 0, false);
    let doc = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
        releases: vec![entry],
    };
    let envelope = manifest::test_support::sign_manifest(&doc);
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let result = serve_envelope_and_check(envelope_json, dir.path()).await;
    assert!(
        matches!(result, Ok(Applicability::HeldBack { .. })),
        "expected HeldBack for a 0% rollout, got {result:?}"
    );
}

/// Same end-to-end path, but the served envelope's signature no
/// longer matches its body (simulating a tampered or corrupted
/// response, or an operator's `resign` step being skipped after an
/// edit): `check_now` must fail closed, never fall back to an
/// unverified manifest and never report an update as available.
#[tokio::test]
async fn a_running_daemon_rejects_a_tampered_manifest() {
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let entry = matching_entry(&mgr, "9.9.9", 100, false);
    let doc = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
        releases: vec![entry],
    };
    let mut envelope = manifest::test_support::sign_manifest(&doc);
    // Mutate the signed body after signing without re-signing --
    // the signature on the wire no longer matches these bytes.
    envelope.manifest_json = envelope.manifest_json.replace("9.9.9", "9.9.8");
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let result = serve_envelope_and_check(envelope_json, dir.path()).await;
    assert!(
        matches!(
            result,
            Err(UpdateError::Manifest(manifest::ManifestError::SignatureVerificationFailed))
        ),
        "expected signature verification to fail (not some unrelated error), got {result:?}"
    );
}

/// Serves `status` for every manifest request, runs `check_now`, and returns
/// its result with the persisted policy.
async fn serve_status_and_check(
    status: u16,
    config_dir: &Path,
) -> (Result<Applicability, UpdateError>, UpdatePolicy) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", format!("{}/manifest.json", server.uri()));
    let mgr = manager(config_dir);
    let result = mgr.check_now().await;
    std::env::remove_var("YADORILINK_UPDATE_MANIFEST_URL");
    (result, mgr.policy.load_or_default())
}

/// Before any release publishes a manifest for a channel the server answers
/// 404. That is "nothing to update to", not a failed check: it must not leave
/// an error category for `status` to raise attention about.
#[tokio::test]
async fn a_channel_with_no_published_manifest_is_up_to_date_not_failed() {
    let dir = tempfile::tempdir().unwrap();
    let (result, policy) = serve_status_and_check(404, dir.path()).await;
    assert!(matches!(result, Ok(Applicability::UpToDate)), "{result:?}");
    assert_eq!(policy.state, UpdateState::UpToDate);
    assert_eq!(policy.last_error_category, None);
    assert!(policy.last_check_unix.is_some());
}

/// Only 404 means "no manifest yet"; a server error is still a failed check.
#[tokio::test]
async fn a_server_error_while_fetching_the_manifest_is_still_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let (result, policy) = serve_status_and_check(500, dir.path()).await;
    assert!(matches!(result, Err(UpdateError::Fetch(_))), "{result:?}");
    assert_eq!(policy.state, UpdateState::Failed);
    assert_eq!(policy.last_error_category.as_deref(), Some("update_manifest_fetch_failed"));
}
