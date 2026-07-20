//! On-disk persistence for the daemon's update policy and last-known
//! update-attempt state — mirrors
//! `governance_config::GovernanceConfigStore`'s exact pattern (a small,
//! independent JSON file under the config directory, `#[serde(default)]`
//! plus a hand-written `Default` so an old/missing file always resolves
//! to a safe default rather than a deserialization error, tempfile-then-
//! rename writes so a crash mid-write never leaves a half-written,
//! unparseable file behind).
//!
//! Living in its own file (not bolted onto `device_config::DeviceConfig`)
//! means an existing install with no `update_policy.json` at all — every
//! device that existed before this update-policy feature shipped —
//! loads the documented safe default (checks/installs enabled, `Idle`
//! state, nothing downloaded) with no migration step, the same
//! "version-safe defaulting for existing installs" property
//! `GovernanceConfigStore`'s own doc comment calls out.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One state per update attempt, persisted so a restart after crash can
/// tell what was in flight. `Idle` is the steady state between checks;
/// `UpToDate` means the most recent check found nothing newer;
/// `HeldBack`/`KillSwitched` mean an applicable-looking newer version
/// exists but isn't currently installable (rollout holdback or a
/// manifest kill-switch entry) — tracked as distinct states (not folded
/// into `Available`) so `yadorilink update status`/`yadorilink status`
/// can say *why* nothing is happening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    #[default]
    Idle,
    Checking,
    Available,
    HeldBack,
    KillSwitched,
    Downloading,
    Downloaded,
    Verified,
    Installing,
    Failed,
    Deferred,
    UpToDate,
}

impl UpdateState {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateState::Idle => "idle",
            UpdateState::Checking => "checking",
            UpdateState::Available => "available",
            UpdateState::HeldBack => "held_back",
            UpdateState::KillSwitched => "kill_switched",
            UpdateState::Downloading => "downloading",
            UpdateState::Downloaded => "downloaded",
            UpdateState::Verified => "verified",
            UpdateState::Installing => "installing",
            UpdateState::Failed => "failed",
            UpdateState::Deferred => "deferred",
            UpdateState::UpToDate => "up_to_date",
        }
    }
}

/// Automatic install is enabled by default only once
/// rollback/interrupted-update tests pass, "for beta builds"
/// specifically. This code doesn't know at compile time whether it's a
/// beta or production build, and shipping "automatic install on by
/// default" as this crate's own hardcoded default before that gate is
/// a policy decision that belongs in release configuration, not here.
/// `Manual` is therefore the safe, conservative default an unset
/// config file resolves to; `main.rs`/packaging is expected to write
/// an explicit `automatic` policy file for a beta build once that gate
/// is satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoInstallMode {
    Automatic,
    #[default]
    Manual,
}

impl AutoInstallMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AutoInstallMode::Automatic => "automatic",
            AutoInstallMode::Manual => "manual",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "automatic" => Some(AutoInstallMode::Automatic),
            "manual" => Some(AutoInstallMode::Manual),
            _ => None,
        }
    }
}

/// A coarse, stable category for the last update-attempt failure — never
/// the raw error text — matching `CliError::report_category`'s
/// established convention in this workspace.
pub type ErrorCategory = String;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdatePolicy {
    pub channel: String,
    pub automatic_checks_enabled: bool,
    pub automatic_install_mode: AutoInstallMode,
    /// Unix seconds; `None` means "never checked".
    pub last_check_unix: Option<i64>,
    pub last_error_category: Option<ErrorCategory>,
    pub last_error_message: Option<String>,
    pub state: UpdateState,
    pub available_version: Option<String>,
    pub available_release_notes_url: Option<String>,
    pub mandatory: bool,
    pub holdback_reason: Option<String>,
    /// Set once a downloaded artifact has passed *both* checksum and
    /// platform-signature verification (`verify::verify_artifact`) —
    /// `manager::recover_on_startup` treats an artifact whose path is set
    /// here but this flag is `false` as untrusted and discards it,
    /// regardless of why the daemon didn't get to update this flag last
    /// time (crash, kill -9, power loss).
    pub downloaded_artifact_path: Option<PathBuf>,
    pub downloaded_artifact_verified: bool,
    /// A stable value in `0..100`, generated once and persisted forever
    /// (never re-rolled), used only locally to decide staged-rollout
    /// eligibility (`manifest::LocalContext::rollout_bucket`) — never
    /// sent in any update-check request (see
    /// the update privacy rule).
    pub rollout_bucket: u8,
    /// The account's
    /// stable beta cohort, or `None` for a non-tester. Populated by the
    /// client (desktop/CLI) from the coordination plane's `GET /account/beta`
    /// and persisted here; the daemon reads it only to derive a *stable*
    /// rollout bucket for a tester (see `effective_rollout_bucket`), so a
    /// cohort maps consistently onto the manifest's rollout percentage
    /// release-over-release rather than being re-bucketed each release. Like
    /// `rollout_bucket`, it is never sent in an update-check request.
    #[serde(default)]
    pub beta_cohort: Option<String>,
}

/// A deterministic, platform- and release-stable `0..100` bucket for a beta
/// cohort. FNV-1a over the cohort bytes (implemented inline so the mapping
/// never depends on an unstable `std` hash) taken mod 100, so every install
/// in the same cohort maps to the same bucket, release-over-release. This is
/// what makes a staged rollout target *real, stable cohorts* rather than an
/// opaque per-install hash bucket.
fn cohort_rollout_bucket(cohort: &str) -> u8 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in cohort.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash % 100) as u8
}

impl UpdatePolicy {
    /// The rollout bucket the update check should use. A beta tester's bucket
    /// is a stable function of their cohort, so all of a tester's installs
    /// (and every install in that cohort) fall inside or outside a given
    /// rollout percentage together, consistently across releases. A
    /// non-tester keeps the ordinary per-install `rollout_bucket`, so
    /// non-tester behavior is entirely unchanged.
    pub fn effective_rollout_bucket(&self) -> u8 {
        match &self.beta_cohort {
            Some(cohort) => cohort_rollout_bucket(cohort),
            None => self.rollout_bucket,
        }
    }
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        UpdatePolicy {
            // Public beta builds default to the `beta` channel. This
            // crate has no separate beta/production build flag today,
            // so `beta` is this crate's default for every install
            // until release packaging introduces one.
            channel: "beta".to_string(),
            automatic_checks_enabled: true,
            automatic_install_mode: AutoInstallMode::default(),
            last_check_unix: None,
            last_error_category: None,
            last_error_message: None,
            state: UpdateState::Idle,
            available_version: None,
            available_release_notes_url: None,
            mandatory: false,
            holdback_reason: None,
            downloaded_artifact_path: None,
            downloaded_artifact_verified: false,
            rollout_bucket: 0,
            beta_cohort: None,
        }
    }
}

pub struct UpdatePolicyStore {
    path: PathBuf,
}

impl UpdatePolicyStore {
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        UpdatePolicyStore { path: config_dir.as_ref().join("update_policy.json") }
    }

    /// Reads the persisted policy, or the documented default if no file
    /// has ever been written. Deliberately does **not** write anything to
    /// disk, so simply loading (or `load_or_default`) can never turn a
    /// fresh install into one with an update-policy file on disk.
    pub fn load(&self) -> std::io::Result<UpdatePolicy> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UpdatePolicy {
                rollout_bucket: fresh_rollout_bucket(),
                ..UpdatePolicy::default()
            }),
            Err(e) => Err(e),
        }
    }

    pub fn load_or_default(&self) -> UpdatePolicy {
        match self.load() {
            Ok(policy) => policy,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %self.path.display(),
                    "update-policy: failed to load config; using defaults"
                );
                UpdatePolicy { rollout_bucket: fresh_rollout_bucket(), ..UpdatePolicy::default() }
            }
        }
    }

    /// Writes to a temp file and renames over the target, matching
    /// `GovernanceConfigStore::save`'s crash-safety discipline.
    pub fn save(&self, policy: &UpdatePolicy) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(policy)?;
        let tmp_path = self.path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Loads the current policy (assigning a fresh `rollout_bucket` the
    /// very first time, so it's persisted from that point on), applies
    /// `mutate`, saves, and returns the resulting policy — the standard
    /// read-modify-write shape every control-socket update-policy handler
    /// uses.
    pub fn update(&self, mutate: impl FnOnce(&mut UpdatePolicy)) -> std::io::Result<UpdatePolicy> {
        let mut policy = self.load_or_default();
        mutate(&mut policy);
        self.save(&policy)?;
        Ok(policy)
    }
}

fn fresh_rollout_bucket() -> u8 {
    rand::random_range(0..100)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, UpdatePolicyStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = UpdatePolicyStore::new(dir.path());
        (dir, store)
    }

    /// A fresh install (no file yet) reports the documented safe
    /// defaults without writing anything to disk.
    #[test]
    fn fresh_store_reports_defaults_without_writing_a_file() {
        let (dir, store) = store();
        let policy = store.load().unwrap();
        assert_eq!(policy.channel, "beta");
        assert!(policy.automatic_checks_enabled);
        assert_eq!(policy.automatic_install_mode, AutoInstallMode::Manual);
        assert_eq!(policy.state, UpdateState::Idle);
        assert!(!dir.path().join("update_policy.json").exists());
    }

    #[test]
    fn update_persists_across_a_new_store_instance() {
        let (dir, store) = store();
        let policy = store
            .update(|p| {
                p.state = UpdateState::Available;
                p.available_version = Some("0.2.0".into());
            })
            .unwrap();
        assert_eq!(policy.state, UpdateState::Available);

        let reopened = UpdatePolicyStore::new(dir.path());
        assert_eq!(reopened.load().unwrap(), policy);
    }

    /// The rollout bucket is assigned once and then stable across
    /// reloads — not re-randomized on every `load_or_default` call before
    /// anything has been saved.
    #[test]
    fn rollout_bucket_is_stable_once_persisted() {
        let (_dir, store) = store();
        let first = store.update(|_| {}).unwrap();
        let second = store.load().unwrap();
        assert_eq!(first.rollout_bucket, second.rollout_bucket);
    }

    /// An old/hand-edited config file missing fields must still
    /// deserialize to safe defaults for the absent fields, never a hard
    /// error — matches `GovernanceConfigStore`'s own established
    /// discipline.
    #[test]
    fn deserializing_a_partial_json_object_fills_in_safe_defaults() {
        let (dir, store) = store();
        std::fs::write(dir.path().join("update_policy.json"), r#"{"channel": "stable"}"#).unwrap();
        let policy = store.load().unwrap();
        assert_eq!(policy.channel, "stable");
        assert!(policy.automatic_checks_enabled); // filled in, not a hard error
        assert_eq!(policy.state, UpdateState::Idle);
    }

    /// Crash-recovery precondition: an artifact path can be
    /// recorded without `downloaded_artifact_verified` ever being set,
    /// and that round-trips faithfully (the flag is never implicitly
    /// upgraded to `true` just because a path is present).
    #[test]
    fn unverified_downloaded_artifact_path_round_trips_as_unverified() {
        let (_dir, store) = store();
        let policy = store
            .update(|p| {
                p.downloaded_artifact_path = Some(PathBuf::from("/tmp/update.pkg"));
                p.state = UpdateState::Downloaded;
            })
            .unwrap();
        assert!(!policy.downloaded_artifact_verified);
        assert_eq!(policy.downloaded_artifact_path, Some(PathBuf::from("/tmp/update.pkg")));
    }

    // Cohort-based
    // rollout maps a tester's stable cohort onto the manifest rollout
    // percentage, stably across releases; non-testers are unaffected.
    use super::super::manifest::{
        select_applicable, Applicability, LocalContext, ReleaseEntry, UpdateManifest,
    };

    fn release_entry(version: &str, rollout_percentage: u8) -> ReleaseEntry {
        ReleaseEntry {
            channel: "beta".into(),
            platform: "macos".into(),
            arch: "aarch64".into(),
            install_source: "standalone".into(),
            version: version.into(),
            minimum_supported_version: "0.1.0".into(),
            rollout_percentage,
            kill_switch: false,
            mandatory: false,
            artifact_url: "https://example.invalid/yadorilink.pkg".into(),
            artifact_sha256: "0".repeat(64),
            artifact_size: Some(1024),
            artifact_publisher_identity: String::new(),
            release_notes_url: String::new(),
        }
    }

    fn manifest_with(entry: ReleaseEntry) -> UpdateManifest {
        UpdateManifest {
            schema_version: 1,
            generated_at: "2026-01-01T00:00:00Z".into(),
            releases: vec![entry],
        }
    }

    fn ctx_for(policy: &UpdatePolicy, current: &str) -> LocalContext {
        LocalContext {
            current_version: semver::Version::parse(current).unwrap(),
            channel: "beta".into(),
            platform: "macos".into(),
            arch: "aarch64".into(),
            install_source: "standalone".into(),
            rollout_bucket: policy.effective_rollout_bucket(),
        }
    }

    #[test]
    fn cohort_bucket_is_deterministic_and_in_range() {
        let b = cohort_rollout_bucket("beta-wave-1");
        assert_eq!(b, cohort_rollout_bucket("beta-wave-1"));
        assert!(b < 100);
        assert_ne!(cohort_rollout_bucket("beta-wave-1"), cohort_rollout_bucket("beta-wave-2"));
    }

    #[test]
    fn effective_bucket_uses_cohort_for_testers_and_per_install_for_non_testers() {
        let tester = UpdatePolicy {
            beta_cohort: Some("beta-wave-1".into()),
            rollout_bucket: 7,
            ..Default::default()
        };
        // A tester's bucket is a function of the cohort, not the per-install value.
        assert_eq!(tester.effective_rollout_bucket(), cohort_rollout_bucket("beta-wave-1"));
        // A non-tester keeps the ordinary per-install bucket.
        let non_tester =
            UpdatePolicy { beta_cohort: None, rollout_bucket: 7, ..Default::default() };
        assert_eq!(non_tester.effective_rollout_bucket(), 7);
    }

    #[test]
    fn cohort_inside_the_rollout_percentage_selects_the_update_stably_across_releases() {
        let cohort = "beta-wave-1";
        let bucket = cohort_rollout_bucket(cohort);
        let tester = UpdatePolicy {
            beta_cohort: Some(cohort.into()),
            rollout_bucket: 99,
            ..Default::default()
        };

        // A rollout percentage just above the cohort's bucket includes it.
        let inside_pct = bucket + 1; // bucket < 100, so this is <= 100
        for version in ["0.5.0", "0.6.0"] {
            let manifest = manifest_with(release_entry(version, inside_pct));
            let ctx = ctx_for(&tester, "0.4.0");
            assert!(
                matches!(select_applicable(&manifest, &ctx), Applicability::Available { .. }),
                "cohort inside {inside_pct}% rollout should select {version}",
            );
        }

        // Stable across releases: the same cohort bucket drives every release,
        // so the tester is never re-bucketed release-over-release.
        assert_eq!(
            ctx_for(&tester, "0.4.0").rollout_bucket,
            ctx_for(&tester, "0.5.0").rollout_bucket
        );
        assert_eq!(ctx_for(&tester, "0.4.0").rollout_bucket, bucket);
    }

    #[test]
    fn cohort_outside_the_rollout_percentage_is_held_back() {
        let cohort = "beta-wave-1";
        let bucket = cohort_rollout_bucket(cohort);
        // A rollout percentage equal to the bucket excludes it (bucket < pct is false).
        if bucket > 0 {
            let tester = UpdatePolicy { beta_cohort: Some(cohort.into()), ..Default::default() };
            let manifest = manifest_with(release_entry("0.5.0", bucket));
            let ctx = ctx_for(&tester, "0.4.0");
            assert!(matches!(select_applicable(&manifest, &ctx), Applicability::HeldBack { .. }));
        }
    }

    #[test]
    fn non_tester_rollout_behavior_is_unchanged() {
        // A non-tester's context bucket is exactly the persisted per-install
        // value, so rollout selection is identical to before this change.
        let non_tester =
            UpdatePolicy { beta_cohort: None, rollout_bucket: 10, ..Default::default() };
        let ctx = ctx_for(&non_tester, "0.4.0");
        assert_eq!(ctx.rollout_bucket, 10);
        assert!(matches!(
            select_applicable(&manifest_with(release_entry("0.5.0", 11)), &ctx),
            Applicability::Available { .. }
        ));
        assert!(matches!(
            select_applicable(&manifest_with(release_entry("0.5.0", 10)), &ctx),
            Applicability::HeldBack { .. }
        ));
    }
}
