//! add-automatic-updates task 2: orchestrates manifest checks, artifact
//! download/verification, and install dispatch on top of `manifest`,
//! `verify`, and `policy`; also owns interrupted-update recovery on
//! daemon startup (task 2.5).
//!
//! Nothing in this module ever installs or trusts an artifact except
//! through the exact sequence: fetch manifest -> `manifest::verify_and_parse`
//! (signature) -> `manifest::select_applicable` (applicability/downgrade/
//! rollout/kill-switch) -> download -> `verify::verify_checksum` +
//! `verify::verify_*_signature` (both must pass) -> only then is
//! `policy.downloaded_artifact_verified` ever set to `true`, and only a
//! `true` there is ever handed to a platform installer.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::manifest::{self, Applicability, LocalContext, ReleaseEntry};
use super::policy::{AutoInstallMode, UpdatePolicy, UpdatePolicyStore, UpdateState};
use super::verify::{self, CommandRunner, SystemCommandRunner};
use super::{install_macos, install_windows};

#[derive(Debug, Clone, thiserror::Error)]
pub enum UpdateError {
    #[error("failed to fetch update manifest: {0}")]
    Fetch(String),
    #[error("update manifest rejected: {0}")]
    Manifest(#[from] manifest::ManifestError),
    #[error("failed to download update artifact: {0}")]
    Download(String),
    #[error("update artifact verification failed: {0}")]
    Verify(#[from] verify::VerifyError),
    #[error("no verified update is ready to install")]
    NoVerifiedUpdate,
    #[error("install failed: {0}")]
    Install(String),
    #[error("unsupported platform for automatic updates")]
    UnsupportedPlatform,
    #[error("failed to persist update policy: {0}")]
    Policy(String),
}

impl From<std::io::Error> for UpdateError {
    fn from(e: std::io::Error) -> Self {
        UpdateError::Policy(e.to_string())
    }
}

impl UpdateError {
    /// A coarse, stable category — never the raw message — matching this
    /// workspace's `CliError::report_category` convention, stored in
    /// `UpdatePolicy::last_error_category`.
    pub fn category(&self) -> &'static str {
        match self {
            UpdateError::Fetch(_) => "update_manifest_fetch_failed",
            UpdateError::Manifest(_) => "update_manifest_invalid",
            UpdateError::Download(_) => "update_artifact_download_failed",
            UpdateError::Verify(_) => "update_artifact_verification_failed",
            UpdateError::NoVerifiedUpdate => "update_no_verified_artifact",
            UpdateError::Install(_) => "update_install_failed",
            UpdateError::UnsupportedPlatform => "update_unsupported_platform",
            UpdateError::Policy(_) => "update_policy_persist_failed",
        }
    }
}

/// This install's coarse platform identity — never anything more
/// identifying (device id, account id) — task 1's `LocalContext` plus the
/// Windows install-source distinction from `install_windows`.
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub platform: String,
    pub arch: String,
    pub install_source: String,
}

impl PlatformInfo {
    pub fn detect() -> Self {
        let platform = if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            "linux"
        }
        .to_string();
        let arch = std::env::consts::ARCH.to_string();
        let install_source = detect_install_source();
        PlatformInfo { platform, arch, install_source }
    }
}

#[cfg(windows)]
fn detect_install_source() -> String {
    let exe = std::env::current_exe().unwrap_or_default();
    install_windows::detect_install_source(&exe).as_str().to_string()
}

#[cfg(not(windows))]
fn detect_install_source() -> String {
    "standalone".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallDispatchOutcome {
    Deferred,
    StoreManaged { guidance: String },
    HandoffLaunched,
    Installed,
}

pub struct UpdateManager {
    pub policy: UpdatePolicyStore,
    http: reqwest::Client,
    manifest_url: String,
    updates_dir: PathBuf,
    current_version: semver::Version,
    platform_info: PlatformInfo,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl UpdateManager {
    /// `manifest_url` is overridable via `YADORILINK_UPDATE_MANIFEST_URL`
    /// (mirrors this crate's existing `YADORILINK_*` env-var override
    /// convention for socket/db paths in `main.rs`) so this is testable
    /// against a local mock server without touching production config;
    /// no manifest is served for this beta yet, so the built-in default is
    /// a documented placeholder.
    pub fn new(config_dir: impl AsRef<Path>, current_version: semver::Version) -> Self {
        let manifest_url = std::env::var("YADORILINK_UPDATE_MANIFEST_URL").unwrap_or_else(|_| {
            "https://updates.yadorilink.example/beta/manifest.json".to_string()
        });
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(format!("yadorilink-daemon/{current_version}"))
            .build()
            .expect("reqwest client construction with only timeout/user-agent set cannot fail");
        UpdateManager {
            policy: UpdatePolicyStore::new(config_dir.as_ref()),
            http,
            manifest_url,
            updates_dir: config_dir.as_ref().join("updates"),
            current_version,
            platform_info: PlatformInfo::detect(),
        }
    }

    pub fn current_version(&self) -> &semver::Version {
        &self.current_version
    }

    pub fn platform_info(&self) -> &PlatformInfo {
        &self.platform_info
    }

    fn local_context(&self, policy: &UpdatePolicy) -> LocalContext {
        LocalContext {
            current_version: self.current_version.clone(),
            channel: policy.channel.clone(),
            platform: self.platform_info.platform.clone(),
            arch: self.platform_info.arch.clone(),
            install_source: self.platform_info.install_source.clone(),
            rollout_bucket: policy.rollout_bucket,
        }
    }

    /// task 2.2/2.3: fetches and verifies the manifest, decides
    /// applicability, and persists the resulting state — never downloads
    /// or installs anything itself. Callable both from the periodic
    /// scheduler and directly from `yadorilink update check`.
    pub async fn check_now(&self) -> Result<Applicability, UpdateError> {
        let _ = self.policy.update(|p| p.state = UpdateState::Checking);
        let result = self.check_now_inner().await;
        match &result {
            Ok(applicability) => {
                self.record_applicability(applicability)?;
            }
            Err(e) => {
                self.policy.update(|p| {
                    p.state = UpdateState::Failed;
                    p.last_error_category = Some(e.category().to_string());
                    p.last_error_message = Some(e.to_string());
                    p.last_check_unix = Some(now_unix());
                })?;
            }
        }
        result
    }

    async fn check_now_inner(&self) -> Result<Applicability, UpdateError> {
        let policy = self.policy.load_or_default();
        let response = self
            .http
            .get(&self.manifest_url)
            .query(&self.update_check_query(&policy))
            .send()
            .await
            .map_err(|e| UpdateError::Fetch(e.to_string()))?;
        let response =
            response.error_for_status().map_err(|e| UpdateError::Fetch(e.to_string()))?;
        let body = response.text().await.map_err(|e| UpdateError::Fetch(e.to_string()))?;
        let manifest = manifest::verify_and_parse(&body)?;
        let ctx = self.local_context(&policy);
        Ok(manifest::select_applicable(&manifest, &ctx))
    }

    /// Update privacy:
    /// the *exact* and *only* fields an update-check request carries —
    /// current version, platform, architecture, channel, install source,
    /// and manifest schema version (spec "Update check uses coarse
    /// metadata only"). Deliberately returns a fixed-shape array (not an
    /// extensible map some other call site could accidentally widen) so
    /// there is exactly one place in this codebase that decides what an
    /// update check ever sends — no device id, account id, folder path,
    /// peer address, key, or token is ever constructed as part of this
    /// request.
    fn update_check_query(&self, policy: &UpdatePolicy) -> [(&'static str, String); 6] {
        [
            ("schema_version", manifest::MANIFEST_SCHEMA_VERSION.to_string()),
            ("current_version", self.current_version.to_string()),
            ("platform", self.platform_info.platform.clone()),
            ("arch", self.platform_info.arch.clone()),
            ("channel", policy.channel.clone()),
            ("install_source", self.platform_info.install_source.clone()),
        ]
    }

    fn record_applicability(&self, applicability: &Applicability) -> Result<(), UpdateError> {
        self.policy.update(|p| {
            p.last_check_unix = Some(now_unix());
            p.last_error_category = None;
            p.last_error_message = None;
            match applicability {
                Applicability::UpToDate => {
                    p.state = UpdateState::UpToDate;
                    p.available_version = None;
                    p.available_release_notes_url = None;
                    p.mandatory = false;
                    p.holdback_reason = None;
                }
                Applicability::Available { entry, version, mandatory } => {
                    p.state = UpdateState::Available;
                    p.available_version = Some(version.to_string());
                    p.available_release_notes_url = Some(entry.release_notes_url.clone());
                    p.mandatory = *mandatory;
                    p.holdback_reason = None;
                }
                Applicability::HeldBack { entry, version, reason } => {
                    p.state = UpdateState::HeldBack;
                    p.available_version = Some(version.to_string());
                    p.available_release_notes_url = Some(entry.release_notes_url.clone());
                    p.mandatory = false;
                    p.holdback_reason = Some(reason.clone());
                }
                Applicability::KillSwitched { entry, version } => {
                    p.state = UpdateState::KillSwitched;
                    p.available_version = Some(version.to_string());
                    p.available_release_notes_url = Some(entry.release_notes_url.clone());
                    p.mandatory = false;
                    p.holdback_reason =
                        Some("this release was withdrawn by the publisher (kill switch)".into());
                }
            }
        })?;
        Ok(())
    }

    /// task 2.2/2.6: downloads `entry`'s artifact to a `.partial` path,
    /// verifies checksum + platform publisher signature, and only on
    /// full success renames it into place and marks the policy verified.
    /// Any failure at any step deletes the partial artifact and records
    /// a `Failed` state — this is the fail-closed core the spec's
    /// "Artifact checksum mismatch"/"Artifact publisher signature
    /// mismatch" scenarios describe.
    pub async fn download_and_verify(&self, entry: &ReleaseEntry) -> Result<PathBuf, UpdateError> {
        let result = self.download_and_verify_inner(entry).await;
        if let Err(e) = &result {
            let _ = self.policy.update(|p| {
                p.state = UpdateState::Failed;
                p.last_error_category = Some(e.category().to_string());
                p.last_error_message = Some(e.to_string());
                p.downloaded_artifact_path = None;
                p.downloaded_artifact_verified = false;
            });
        }
        result
    }

    async fn download_and_verify_inner(
        &self,
        entry: &ReleaseEntry,
    ) -> Result<PathBuf, UpdateError> {
        self.policy.update(|p| p.state = UpdateState::Downloading)?;
        std::fs::create_dir_all(&self.updates_dir)
            .map_err(|e| UpdateError::Download(e.to_string()))?;
        let filename = artifact_filename(entry);
        let partial_path = self.updates_dir.join(format!("{filename}.partial"));
        let final_path = self.updates_dir.join(&filename);

        self.stream_download(&entry.artifact_url, &partial_path).await?;
        self.policy.update(|p| p.state = UpdateState::Downloaded)?;

        // Checksum first (cheap, local) before shelling out to a
        // platform tool for the signature check.
        verify::verify_checksum(&partial_path, &entry.artifact_sha256).inspect_err(|_| {
            let _ = std::fs::remove_file(&partial_path);
        })?;

        let runner = SystemCommandRunner;
        self.verify_platform_signature(&runner, &partial_path, entry).inspect_err(|_| {
            let _ = std::fs::remove_file(&partial_path);
        })?;

        std::fs::rename(&partial_path, &final_path)
            .map_err(|e| UpdateError::Download(e.to_string()))?;
        self.policy.update(|p| {
            p.state = UpdateState::Verified;
            p.downloaded_artifact_path = Some(final_path.clone());
            p.downloaded_artifact_verified = true;
        })?;
        Ok(final_path)
    }

    async fn stream_download(&self, url: &str, dest: &Path) -> Result<(), UpdateError> {
        use futures_util::StreamExt;
        use tokio::io::AsyncWriteExt;

        let response =
            self.http.get(url).send().await.map_err(|e| UpdateError::Download(e.to_string()))?;
        let response =
            response.error_for_status().map_err(|e| UpdateError::Download(e.to_string()))?;
        let mut file = tokio::fs::File::create(dest)
            .await
            .map_err(|e| UpdateError::Download(e.to_string()))?;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| UpdateError::Download(e.to_string()))?;
            file.write_all(&chunk).await.map_err(|e| UpdateError::Download(e.to_string()))?;
        }
        file.flush().await.map_err(|e| UpdateError::Download(e.to_string()))?;
        Ok(())
    }

    fn verify_platform_signature(
        &self,
        runner: &dyn CommandRunner,
        path: &Path,
        entry: &ReleaseEntry,
    ) -> Result<(), UpdateError> {
        match self.platform_info.platform.as_str() {
            "macos" => Ok(verify::verify_macos_signature(
                runner,
                path,
                &entry.artifact_publisher_identity,
            )?),
            "windows" => Ok(verify::verify_windows_signature(
                runner,
                path,
                &entry.artifact_publisher_identity,
            )?),
            _ => Err(UpdateError::UnsupportedPlatform),
        }
    }

    /// task 2.4/4: dispatches installation of an already-verified
    /// artifact, gated on `safe_point` (the caller — `daemon_state`'s
    /// safe-point check — decides whether sync-critical writes are in
    /// progress; this function never guesses). Fails closed if the
    /// current policy doesn't actually have a verified artifact,
    /// regardless of what state the caller thinks it's in.
    pub async fn install_now(
        &self,
        safe_point: bool,
    ) -> Result<InstallDispatchOutcome, UpdateError> {
        let policy = self.policy.load_or_default();
        let Some(artifact_path) = policy.downloaded_artifact_path.clone() else {
            return Err(UpdateError::NoVerifiedUpdate);
        };
        if !policy.downloaded_artifact_verified || policy.state != UpdateState::Verified {
            return Err(UpdateError::NoVerifiedUpdate);
        }
        if !safe_point {
            self.policy.update(|p| p.state = UpdateState::Deferred)?;
            return Ok(InstallDispatchOutcome::Deferred);
        }

        self.policy.update(|p| p.state = UpdateState::Installing)?;
        let runner = SystemCommandRunner;
        let outcome = self.dispatch_install(&runner, &artifact_path);
        match &outcome {
            Ok(_) => {
                // The handoff succeeded; the actual replacement now
                // happens outside this process (Installer.app / the
                // Windows installer). Reset to `Idle` rather than
                // claiming `UpToDate` — the daemon doesn't get to
                // observe the OS-level install completing.
                self.policy.update(|p| p.state = UpdateState::Idle)?;
            }
            Err(e) => {
                self.policy.update(|p| {
                    p.state = UpdateState::Failed;
                    p.last_error_category = Some(e.category().to_string());
                    p.last_error_message = Some(e.to_string());
                })?;
            }
        }
        outcome
    }

    fn dispatch_install(
        &self,
        runner: &dyn CommandRunner,
        artifact_path: &Path,
    ) -> Result<InstallDispatchOutcome, UpdateError> {
        match self.platform_info.platform.as_str() {
            "macos" => install_macos::install(runner, artifact_path)
                .map(|_| InstallDispatchOutcome::HandoffLaunched)
                .map_err(|e| UpdateError::Install(e.to_string())),
            "windows" => {
                let source = if self.platform_info.install_source == "microsoft_store" {
                    install_windows::InstallSource::MicrosoftStore
                } else {
                    install_windows::InstallSource::Standalone
                };
                if source == install_windows::InstallSource::MicrosoftStore {
                    return Ok(InstallDispatchOutcome::StoreManaged {
                        guidance:
                            "this install is managed by the Microsoft Store; open Store > Library > Updates to install"
                                .to_string(),
                    });
                }
                install_windows::install(runner, source, artifact_path)
                    .map(|_| InstallDispatchOutcome::Installed)
                    .map_err(|e| UpdateError::Install(e.to_string()))
            }
            _ => Err(UpdateError::UnsupportedPlatform),
        }
    }

    /// task 2.5: interrupted-update recovery, run once at daemon startup
    /// (before the periodic scheduler starts). Any artifact that hadn't
    /// completed verification when the daemon last stopped — whatever
    /// the reason (crash, kill -9, power loss) — is discarded rather than
    /// trusted; an `Installing` state left over from a prior run is
    /// recorded as failed (unknown outcome) rather than assumed
    /// successful, since this process cannot know whether the platform
    /// installer it handed off to actually completed.
    pub fn recover_on_startup(&self) {
        // Defense in depth, independent of what the policy file claims:
        // any stray `*.partial` file is by definition never-verified and
        // is removed unconditionally.
        if let Ok(entries) = std::fs::read_dir(&self.updates_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("partial")
                    && std::fs::remove_file(&path).is_ok()
                {
                    tracing::info!(path = %path.display(), "removed stray unverified update artifact on startup");
                }
            }
        }

        let policy = self.policy.load_or_default();
        match policy.state {
            UpdateState::Downloading | UpdateState::Downloaded => {
                if let Some(path) = &policy.downloaded_artifact_path {
                    let _ = std::fs::remove_file(path);
                }
                let _ = self.policy.update(|p| {
                    p.state = UpdateState::Failed;
                    p.downloaded_artifact_path = None;
                    p.downloaded_artifact_verified = false;
                    p.last_error_category = Some("update_interrupted_download".into());
                    p.last_error_message = Some(
                        "daemon restarted before the previous update artifact finished verification; discarded".into(),
                    );
                });
                tracing::warn!(
                    "discarded an unverified update artifact left over from a previous run"
                );
            }
            UpdateState::Verified if !policy.downloaded_artifact_verified => {
                // Should be unreachable (the two are always set
                // together) but handled explicitly anyway: fail closed,
                // never trust an artifact this flag doesn't vouch for.
                if let Some(path) = &policy.downloaded_artifact_path {
                    let _ = std::fs::remove_file(path);
                }
                let _ = self.policy.update(|p| {
                    p.state = UpdateState::Failed;
                    p.downloaded_artifact_path = None;
                    p.downloaded_artifact_verified = false;
                });
            }
            UpdateState::Installing => {
                let _ = self.policy.update(|p| {
                    p.state = UpdateState::Failed;
                    p.last_error_category = Some("update_interrupted_install".into());
                    p.last_error_message = Some(
                        "daemon restarted during an install handoff; outcome is unknown -- check platform installer status manually".into(),
                    );
                });
                tracing::warn!("daemon restarted mid-install; recorded as failed for diagnostics (current version remains in use)");
            }
            _ => {}
        }
    }
}

fn artifact_filename(entry: &ReleaseEntry) -> String {
    entry
        .artifact_url
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("update-artifact")
        .to_string()
}

/// task 5.4: applies a `yadorilink update config` change, leaving any
/// field the caller passed `None` for unchanged.
pub fn apply_config(
    store: &UpdatePolicyStore,
    automatic_checks_enabled: Option<bool>,
    automatic_install_mode: Option<AutoInstallMode>,
) -> std::io::Result<UpdatePolicy> {
    store.update(|p| {
        if let Some(enabled) = automatic_checks_enabled {
            p.automatic_checks_enabled = enabled;
        }
        if let Some(mode) = automatic_install_mode {
            p.automatic_install_mode = mode;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `YADORILINK_UPDATE_MANIFEST_URL` is a process-global env var —
    /// every test in this module that touches it holds this mutex for
    /// its whole body, mirroring `daemon_state.rs`'s own
    /// `CONFIG_ENV_MUTEX` precedent for `YADORILINK_CONFIG_DIR`.
    static MANIFEST_URL_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn manager(config_dir: &Path) -> UpdateManager {
        UpdateManager::new(config_dir, semver::Version::parse("0.1.0").unwrap())
    }

    /// design.md's Update Privacy requirement / spec "Update check uses
    /// coarse metadata only": exercises the *real* HTTP request
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
        std::env::set_var(
            "YADORILINK_UPDATE_MANIFEST_URL",
            format!("{}/manifest.json", server.uri()),
        );

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

    /// task 2.6 "crash/restart before verification never installs a
    /// partial artifact": a policy left in `Downloading` with a stray
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

    /// task 2.6: a daemon that crashed mid-install never claims success —
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

    /// task 2.4 "install waits for safe point": a verified artifact is
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
}
