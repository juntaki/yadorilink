#![cfg(test)]

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
        artifact_size: 1024,
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
    let non_tester = UpdatePolicy { beta_cohort: None, rollout_bucket: 7, ..Default::default() };
    assert_eq!(non_tester.effective_rollout_bucket(), 7);
}

#[test]
fn cohort_inside_the_rollout_percentage_selects_the_update_stably_across_releases() {
    let cohort = "beta-wave-1";
    let bucket = cohort_rollout_bucket(cohort);
    let tester =
        UpdatePolicy { beta_cohort: Some(cohort.into()), rollout_bucket: 99, ..Default::default() };

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
    assert_eq!(ctx_for(&tester, "0.4.0").rollout_bucket, ctx_for(&tester, "0.5.0").rollout_bucket);
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
    let non_tester = UpdatePolicy { beta_cohort: None, rollout_bucket: 10, ..Default::default() };
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
