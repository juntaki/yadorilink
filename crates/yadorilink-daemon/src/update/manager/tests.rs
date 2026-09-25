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

/// a policy left in `Downloading` with a stray
/// `.partial` file on disk is cleaned up and reset to `Failed`, never
/// left pointing at a trusted artifact.
#[test]
fn recover_on_startup_discards_unverified_download() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path());
    std::fs::create_dir_all(dir.path().join("updates")).unwrap();
    let partial = dir.path().join("updates/yadorilink-0.2.0.pkg.partial");
    std::fs::write(&partial, b"not yet verified").unwrap();
    manager
        .policy
        .update(|p| {
            p.state = UpdateState::Downloading;
            p.downloaded_artifact_path = Some(partial.clone());
        })
        .unwrap();

    manager.recover_on_startup();

    assert!(!partial.exists(), "stray .partial artifact must be removed on startup");
    let policy = manager.policy.load().unwrap();
    assert_eq!(policy.state, UpdateState::Failed);
    assert!(!policy.downloaded_artifact_verified);
    assert_eq!(policy.downloaded_artifact_path, None);
}

/// The mirror case: a policy in the terminal `Verified` state (a
/// download that genuinely completed *and* passed both checks before
/// the previous run ended) is left alone — recovery must not discard
/// a legitimately verified, still-pending install.
#[test]
fn recover_on_startup_preserves_a_genuinely_verified_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path());
    std::fs::create_dir_all(dir.path().join("updates")).unwrap();
    let artifact = dir.path().join("updates/yadorilink-0.2.0.pkg");
    std::fs::write(&artifact, b"verified bytes").unwrap();
    manager
        .policy
        .update(|p| {
            p.state = UpdateState::Verified;
            p.downloaded_artifact_path = Some(artifact.clone());
            p.downloaded_artifact_verified = true;
        })
        .unwrap();

    manager.recover_on_startup();

    assert!(artifact.exists());
    let policy = manager.policy.load().unwrap();
    assert_eq!(policy.state, UpdateState::Verified);
    assert!(policy.downloaded_artifact_verified);
}

/// a daemon that crashed mid-install never claims success —
/// `Installing` becomes `Failed` with a diagnostic, not `UpToDate`.
#[test]
fn recover_on_startup_marks_interrupted_install_as_failed_not_successful() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path());
    manager.policy.update(|p| p.state = UpdateState::Installing).unwrap();

    manager.recover_on_startup();

    let policy = manager.policy.load().unwrap();
    assert_eq!(policy.state, UpdateState::Failed);
    assert_eq!(policy.last_error_category.as_deref(), Some("update_interrupted_install"));
}

/// `install_now` fails closed when the policy has no verified
/// artifact at all — this is the "never install nothing" guard,
/// independent of the checksum/signature tests in `verify`.
#[tokio::test]
async fn install_now_fails_closed_without_a_verified_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path());
    let result = manager.install_now(true).await;
    assert!(matches!(result, Err(UpdateError::NoVerifiedUpdate)));
}

/// a verified artifact is
/// not installed when `safe_point` is false — the policy state moves
/// to `Deferred`, not `Installing`.
#[tokio::test]
async fn install_now_defers_when_not_at_a_safe_point() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path());
    let artifact = dir.path().join("update.pkg");
    std::fs::write(&artifact, b"x").unwrap();
    manager
        .policy
        .update(|p| {
            p.state = UpdateState::Verified;
            p.downloaded_artifact_path = Some(artifact);
            p.downloaded_artifact_verified = true;
        })
        .unwrap();

    let outcome = manager.install_now(false).await.unwrap();
    assert_eq!(outcome, InstallDispatchOutcome::Deferred);
    assert_eq!(manager.policy.load().unwrap().state, UpdateState::Deferred);
}

/// Sets up a manager with a verified artifact ready to install, then
/// overrides its detected platform/install_source -- `dispatch_install`
/// is pure string matching on those two fields with no `cfg!` inside
/// it, so this exercises the real production dispatch path for every
/// platform's package-manager-deferral branch regardless of which OS
/// actually runs this test suite (unlike `install_linux`/`install_macos`/
/// `install_windows`'s own module tests, which test detection in
/// isolation, this proves `manager::dispatch_install` itself reacts
/// correctly once a source is detected).
fn manager_with_verified_artifact(
    dir: &Path,
    platform: &str,
    install_source: &str,
) -> UpdateManager {
    let mut mgr = manager(dir);
    mgr.platform_info.platform = platform.to_string();
    mgr.platform_info.install_source = install_source.to_string();
    let artifact = dir.join("update-artifact");
    std::fs::write(&artifact, b"x").unwrap();
    mgr.policy
        .update(|p| {
            p.state = UpdateState::Verified;
            p.downloaded_artifact_path = Some(artifact.clone());
            p.downloaded_artifact_verified = true;
        })
        .unwrap();
    mgr
}

/// Package-manager ownership ("package-manager-owned installs never
/// self-update"): a Homebrew
/// Cask install must defer to `brew upgrade`, never launch
/// Installer.app itself.
#[tokio::test]
async fn dispatch_defers_to_brew_for_a_homebrew_managed_macos_install() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager_with_verified_artifact(dir.path(), "macos", "homebrew");

    let outcome = manager.install_now(true).await.unwrap();
    let InstallDispatchOutcome::StoreManaged { guidance } = outcome else {
        panic!("expected StoreManaged, got {outcome:?}");
    };
    assert!(guidance.contains("brew upgrade --cask yadorilink"), "guidance was: {guidance}");
}

/// Same principle, WinGet case: a WinGet-managed Windows install must
/// defer to `winget upgrade`, never run its own standalone installer
/// (the registry-marker path `install_windows::detect_package_manager_marker`
/// feeds into `platform_info.install_source`).
#[tokio::test]
async fn dispatch_defers_to_winget_for_a_winget_managed_windows_install() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager_with_verified_artifact(dir.path(), "windows", "winget");

    let outcome = manager.install_now(true).await.unwrap();
    let InstallDispatchOutcome::StoreManaged { guidance } = outcome else {
        panic!("expected StoreManaged, got {outcome:?}");
    };
    assert!(guidance.contains("winget upgrade yadorilink"), "guidance was: {guidance}");
}

/// Linux has no self-update installer handoff at all yet (see
/// `install_linux`'s module doc), so an apt-managed install must still
/// report the precise, actionable reason rather than a generic
/// "unsupported platform" error.
#[tokio::test]
async fn dispatch_defers_to_apt_for_an_apt_managed_linux_install() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager_with_verified_artifact(dir.path(), "linux", "apt");

    let outcome = manager.install_now(true).await.unwrap();
    let InstallDispatchOutcome::StoreManaged { guidance } = outcome else {
        panic!("expected StoreManaged, got {outcome:?}");
    };
    assert!(guidance.contains("apt install --only-upgrade yadorilink"), "guidance was: {guidance}");
}

/// A non-package-manager (tarball) Linux install has no self-update
/// path at all -- this is pre-existing, still-correct behavior that
/// adding Linux `install_source` detection did not change.
#[tokio::test]
async fn dispatch_is_unsupported_for_a_standalone_linux_install() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager_with_verified_artifact(dir.path(), "linux", "standalone");

    let result = manager.install_now(true).await;
    assert!(matches!(result, Err(UpdateError::UnsupportedPlatform)));
}
